#include "nc_coap_server.h"
#include "nc_coap.h"
#include "nc_client_connection.h"
#include "nc_virtual_connection.h"
#include "nc_connection.h"
#include "nc_coap_packet_printer.h"
#include "nc_device.h"

#include <platform/np_logging.h>
#include <platform/np_timestamp_wrapper.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_allocator.h>

#include <nn/string.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_coap_server_set_infinite_stamp(struct nc_coap_server_context* ctx);
static void nc_coap_server_event_deferred(struct nc_coap_server_context* ctx);
void nc_coap_server_event(struct nc_coap_server_context* ctx);
uint32_t nc_coap_server_get_stamp(void* userData);

void nc_coap_server_notify_event(void* userData);
static np_error_code nc_coap_server_handle_send(struct nc_coap_server_context* ctx);
void nc_coap_server_handle_wait(struct nc_coap_server_context* ctx);
void nc_coap_server_send_to_callback(const np_error_code ec, void* data);
void nc_coap_server_handle_timeout(void* data);

static void nc_coap_server_notify_event_callback(void* userData);

void nc_coap_server_resolve_virtual(np_error_code ec, struct nc_coap_server_request* request);

np_error_code nc_coap_server_init(struct np_platform* pl, struct nc_device_context* device, struct nn_log* logger, struct nc_coap_server_context* ctx)
{
    ctx->sendBuffer = NULL;
    nabto_coap_error err = nabto_coap_server_init(&ctx->server, logger, np_allocator_get());
    nabto_coap_server_requests_init(&ctx->requests, &ctx->server, &nc_coap_server_get_stamp, &nc_coap_server_notify_event, ctx);
    if (err != NABTO_COAP_ERROR_OK) {
        return nc_coap_error_to_core(err);
    }
    ctx->pl = pl;
    ctx->device = device;
    nc_coap_server_set_infinite_stamp(ctx);
    np_error_code ec;
    ec = np_event_queue_create_event(&pl->eq, &nc_coap_server_notify_event_callback, ctx, &ctx->ev);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_event_queue_create_event(&pl->eq, &nc_coap_server_handle_timeout, ctx, &ctx->timer);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(&pl->eq, &ctx->sendCtx.ev, &nc_coap_server_send_to_callback, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    return NABTO_EC_OK;
}

void nc_coap_server_deinit(struct nc_coap_server_context* ctx)
{
    if (ctx->pl != NULL) { // if init was called
        nabto_coap_server_requests_destroy(&ctx->requests);
        nabto_coap_server_destroy(&ctx->server);

        struct np_event_queue* eq = &ctx->pl->eq;
        np_event_queue_destroy_event(eq, ctx->ev);
        np_event_queue_destroy_event(eq, ctx->timer);
        np_completion_event_deinit(&ctx->sendCtx.ev);
    }
}

void nc_coap_server_handle_packet(struct nc_coap_server_context* ctx, struct nc_client_connection* conn,
                                  uint8_t* buffer, uint16_t bufferSize)
{
    // TODO: maybe use nc_connection instead of client_connection
    nc_coap_packet_print("coap server handle packet", buffer, bufferSize);
    nabto_coap_server_handle_packet(&ctx->requests,(void*) conn, buffer, bufferSize);
    nc_coap_server_event(ctx);
}

void nc_coap_server_event(struct nc_coap_server_context* ctx)
{
    enum nabto_coap_server_next_event nextEvent =
        nabto_coap_server_next_event(&ctx->requests);
    if (nextEvent == NABTO_COAP_SERVER_NEXT_EVENT_SEND) {
        np_error_code ec = nc_coap_server_handle_send(ctx);
        if (ec == NABTO_EC_OPERATION_STARTED ||
            ec == NABTO_EC_OPERATION_IN_PROGRESS) {
            // we are waiting for an async operation before doing the next
            // thing
            return;
        } else {
            nc_coap_server_event_deferred(ctx);
        }
    } else if (nextEvent == NABTO_COAP_SERVER_NEXT_EVENT_WAIT) {
        nc_coap_server_handle_wait(ctx);
        return;
    } else if (nextEvent == NABTO_COAP_SERVER_NEXT_EVENT_NOTHING) {
        return;
    }
}

np_error_code nc_coap_server_handle_send(struct nc_coap_server_context* ctx)
{
    struct np_platform* pl = ctx->pl;

    if (ctx->sendBuffer != NULL) {
        //NABTO_LOG_TRACE(LOG, "handle send, isSending: %i", ctx->isSending );
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }

    void* connection = nabto_coap_server_get_connection_send(&ctx->requests);
    if (!connection) {
        // this should not really happen.
        return NABTO_EC_NO_OPERATION;
    }
    struct nc_client_connection* clientConnection = (struct nc_client_connection*)connection;

    ctx->sendBuffer = pl->buf.allocate();
    if (ctx->sendBuffer == NULL) {
        NABTO_LOG_ERROR(LOG, "canot allocate buffer for sending a packet from the coap server.");
        // discard the packet
        nabto_coap_server_handle_send(&ctx->requests, NULL, NULL);
        return NABTO_EC_OUT_OF_MEMORY;
    }
    uint8_t* sendBuffer = pl->buf.start(ctx->sendBuffer);
    size_t sendBufferSize = pl->buf.size(ctx->sendBuffer);

    uint8_t* sendEnd = nabto_coap_server_handle_send(&ctx->requests, sendBuffer, sendBuffer + sendBufferSize);

    if (sendEnd == NULL || sendEnd < sendBuffer) {
        // this should not happen

        pl->buf.free(ctx->sendBuffer);
        ctx->sendBuffer = NULL;
        return NABTO_EC_UNKNOWN;
    }

    struct np_dtls_send_context* sendCtx = &ctx->sendCtx;
    sendCtx->buffer = sendBuffer;
    sendCtx->bufferSize = (uint16_t)(sendEnd - sendBuffer);
    sendCtx->channelId = NP_DTLS_CLI_DEFAULT_CHANNEL_ID;
    nc_coap_packet_print("coap server send packet", sendCtx->buffer, sendCtx->bufferSize);
    // TODO handle send errors.
    nc_client_connection_async_send_data(clientConnection, sendCtx);
    return NABTO_EC_OPERATION_STARTED;
}

void nc_coap_server_handle_wait(struct nc_coap_server_context* ctx)
{
    uint32_t nextStamp;
    nabto_coap_server_get_next_timeout(&ctx->requests, &nextStamp);
    if (nabto_coap_is_stamp_less(nextStamp, ctx->currentExpiry)) {
        ctx->currentExpiry = nextStamp;
        uint32_t now = nabto_coap_server_stamp_now(&ctx->requests);
        int32_t diff = nabto_coap_stamp_diff(nextStamp, now);
        if (diff < 0) {
            diff = 0;
        }
        np_event_queue_post_timed_event(&ctx->pl->eq, ctx->timer, diff);
    }
}

void nc_coap_server_handle_timeout(void* data)
{
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*) data;
    //NABTO_LOG_TRACE(LOG, "Handle timeout called");
    nc_coap_server_set_infinite_stamp(ctx);
    nabto_coap_server_handle_timeout(&ctx->requests);
    nc_coap_server_event(ctx);
}

bool nc_coap_server_context_request_get_connection_id(struct nc_coap_server_context* ctx, struct nc_coap_server_request* request, uint8_t* connectionId)
{
    (void)ctx;
    if (request->isVirtual) {
        return false;
    }
    struct nc_client_connection* conn = (struct nc_client_connection*)nabto_coap_server_request_get_connection(request->request);
    memcpy(connectionId, conn->id.id+1, 14);
    return true;
}

void nc_coap_server_remove_connection(struct nc_coap_server_context* ctx, struct nc_connection* connection)
{
    if (connection->isVirtual) {
        struct nc_virtual_connection* virConn = connection->connectionImplCtx;
        struct nc_coap_server_request* request;
        NN_LLIST_FOREACH(request, &virConn->coapRequests) {
            request->virRequest->connectionClosed = true;
            nc_coap_server_resolve_virtual(NABTO_EC_STOPPED, request);
        }

    } else {
        NABTO_LOG_TRACE(LOG, "Removing connection from coap server.");
        nabto_coap_server_remove_connection(&ctx->requests, connection->connectionImplCtx);
    }
}

// ========= UTIL FUNCTIONS ============= //
void nc_coap_server_send_to_callback(const np_error_code ec, void* data)
{
    (void)ec;
    struct nc_coap_server_context* ctx = data;
    struct np_platform* pl = ctx->pl;
    pl->buf.free(ctx->sendBuffer);
    ctx->sendBuffer = NULL;
    nc_coap_server_event(ctx);
}

uint32_t nc_coap_server_get_stamp(void* userData) {
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*)userData;
    return np_timestamp_now_ms(&ctx->pl->timestamp);
}

void nc_coap_server_notify_event_callback(void* userData)
{
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*)userData;
    nc_coap_server_event(ctx);
}

void nc_coap_server_event_deferred(struct nc_coap_server_context* ctx)
{
    np_event_queue_post_maybe_double(&ctx->pl->eq, ctx->ev);
}

void nc_coap_server_notify_event(void* userData)
{
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*)userData;
    nc_coap_server_event_deferred(ctx);
}

void nc_coap_server_set_infinite_stamp(struct nc_coap_server_context* ctx)
{
    ctx->currentExpiry = nabto_coap_server_stamp_now(&ctx->requests);
    ctx->currentExpiry += (1 << 29);
}

void nc_coap_server_limit_requests(struct nc_coap_server_context* ctx, size_t limit)
{
    // TODO: virtual
    nabto_coap_server_limit_requests(&ctx->requests, limit);
}


void resource_callback(struct nabto_coap_server_request* request, void* userData)
{
    struct nc_coap_server_resource* res = (struct nc_coap_server_resource*)userData;
    struct nc_coap_server_request* req = np_calloc(1, sizeof(struct nc_coap_server_request));
    req->request = request;
    req->device = res->device;
    req->isVirtual = false;
    res->handler(req, res->userData);
}


nabto_coap_error nc_coap_server_add_resource(struct nc_coap_server_context* server, nabto_coap_code method, const char** segments, nc_coap_server_resource_handler handler, void* userData, struct nc_coap_server_resource** resource)
{
    *resource = np_calloc(1, sizeof(struct nc_coap_server_resource));
    if (*resource == NULL) {
        return NABTO_COAP_ERROR_OUT_OF_MEMORY;
    }
    (*resource)->handler = handler;
    (*resource)->userData = userData;
    (*resource)->device = server->device;
    nn_llist_init(&(*resource)->virtualRequests);
    return nabto_coap_server_add_resource(&server->server, method, segments, &resource_callback, *resource, &(*resource)->resource);
}

void nc_coap_server_remove_resource(struct nc_coap_server_resource* resource)
{
    nabto_coap_server_remove_resource(resource->resource);
    struct nc_coap_server_request* req;
    struct nn_llist_iterator it = nn_llist_begin(&resource->virtualRequests);
    while(!nn_llist_is_end(&it)) {
        req = nn_llist_get_item(&it);
        nn_llist_next(&it);
        nc_coap_server_send_error_response(req, NABTO_COAP_CODE_NOT_FOUND, "Resource not found");
    }
    np_free(resource);
}

nabto_coap_error nc_coap_server_send_error_response(struct nc_coap_server_request* request, nabto_coap_code status, const char* description)
{
    if (request->isVirtual) {
        request->virRequest->respStatusCode = status;
        if (description != NULL) {
            request->virRequest->respPayload = nn_strdup(description, np_allocator_get());
            request->virRequest->respPayloadSize = strlen(description);
        }
        request->virRequest->responseReady = true;
        nc_coap_server_resolve_virtual(NABTO_EC_OK, request);
        return NABTO_COAP_ERROR_OK;
    }
    return nabto_coap_server_send_error_response(request->request, status, description);
}

void nc_coap_server_response_set_code(struct nc_coap_server_request* request, nabto_coap_code code)
{
    if (request->isVirtual) {
        request->virRequest->respStatusCode = code;
        return;
    }
    return nabto_coap_server_response_set_code(request->request, code);
}
void nc_coap_server_response_set_code_human(struct nc_coap_server_request* request, uint16_t humanCode)
{
    if (request->isVirtual) {
        int code = humanCode % 100;
        int klass = humanCode / 100;
        request->virRequest->respStatusCode = (nabto_coap_code)(NABTO_COAP_CODE(klass, code));
        return;
    }
    return nabto_coap_server_response_set_code_human(request->request, humanCode);
}

nabto_coap_error nc_coap_server_response_set_payload(struct nc_coap_server_request* request, const void* data, size_t dataSize)
{
    if (request->isVirtual) {
        request->virRequest->respPayload = np_calloc(1, dataSize);
        if (request->virRequest->respPayload == NULL) {
            return NABTO_COAP_ERROR_OUT_OF_MEMORY;
        }
        memcpy(request->virRequest->respPayload, data, dataSize);
        request->virRequest->respPayloadSize = dataSize;
        return NABTO_COAP_ERROR_OK;
    }
    return nabto_coap_server_response_set_payload(request->request, data, dataSize);
}

void nc_coap_server_response_set_content_format(struct nc_coap_server_request* request, uint16_t format)
{
    if (request->isVirtual) {
        request->virRequest->respContentFormat = format;
        return;
    }
    return nabto_coap_server_response_set_content_format(request->request, format);
}

nabto_coap_error nc_coap_server_response_ready(struct nc_coap_server_request* request)
{
    if (request->isVirtual) {
        // If connection is closed, the virtual request is already resolved
        if (!request->virRequest->connectionClosed) {
            request->virRequest->responseReady = true;
            nc_coap_server_resolve_virtual(NABTO_EC_OK, request);
        }
        return NABTO_COAP_ERROR_OK;
    }

    return nabto_coap_server_response_ready(request->request);
}

void do_free_virtual_request(struct nc_coap_server_request* request)
{
    if (!request->virRequest->connectionClosed) {
        // If connection is closed, the list is already deinit
        nc_virtual_connection_remove_coap_request(request->virRequest->connection->connectionImplCtx, request);
    }
    nn_string_map_deinit(&request->virRequest->parameters);
    np_free(request->virRequest->reqPayload);
    np_free(request->virRequest->respPayload);
    np_free(request->virRequest);
    np_free(request);
}

void nc_coap_server_request_free(struct nc_coap_server_request* request)
{
    if (!request->isVirtual) {
        nabto_coap_server_request_free(request->request);
        np_free(request);
    } else {
        request->virRequest->serverFreed = true;
        if (request->virRequest->clientFreed) {
            do_free_virtual_request(request);
        }
    }
}

void nc_coap_server_virtual_request_free(struct nc_coap_server_request* request)
{
    if (request->isVirtual) {
        request->virRequest->clientFreed = true;
        if (request->virRequest->serverFreed) {
            do_free_virtual_request(request);
        }
    }
}

/**
 * Get content format, if no content format is present return -1 else
 * a contentFormat between 0 and 2^16-1 is returned.
 */
int32_t nc_coap_server_request_get_content_format(struct nc_coap_server_request* request)
{
    if (request->isVirtual) {
        return request->virRequest->reqContentFormat;
    }
    return nabto_coap_server_request_get_content_format(request->request);
}

bool nc_coap_server_request_get_payload(struct nc_coap_server_request* request, void** payload, size_t* payloadLength)
{
    if (request->isVirtual) {
        *payload = request->virRequest->reqPayload;
        *payloadLength = request->virRequest->reqPayloadSize;
        return true;
    }
    return nabto_coap_server_request_get_payload(request->request,payload, payloadLength);
}

void* nc_coap_server_request_get_connection(struct nc_coap_server_request* request)
{
    if (request->isVirtual) {
        return request->virRequest->connection;
    } else {
        struct nc_client_connection* cliConn = nabto_coap_server_request_get_connection(request->request);
        return nc_connections_connection_from_client_connection(&request->device->connections, cliConn);
    }
}

uint64_t nc_coap_server_request_get_connection_ref(struct nc_coap_server_request* request)
{
    struct nc_connection* connection = NULL;
    if (request->isVirtual) {
        connection = request->virRequest->connection;
    } else {
        struct nc_client_connection* cliConn = (struct nc_client_connection*)nabto_coap_server_request_get_connection(request->request);
        connection = nc_connections_connection_from_client_connection(&request->device->connections, cliConn);
    }
    if (connection != NULL) {
        return connection->connectionRef;
    }
    return 0;
}

const char* nc_coap_server_request_get_parameter(struct nc_coap_server_request* request, const char* parameter)
{
    if (request->isVirtual) {
        struct nn_string_map_iterator it = nn_string_map_get(&request->virRequest->parameters, parameter);
        if (nn_string_map_is_end(&it)) {
            return NULL;
        } else {
            return nn_string_map_value(&it);
        }
    } else {
        return nabto_coap_server_request_get_parameter(request->request, parameter);
    }
}


struct nc_coap_server_request* nc_coap_server_create_virtual_request(struct nc_coap_server_context* ctx, struct nc_connection* conn,
nabto_coap_code method, const char** segments, void* payload, size_t payloadSize, uint16_t contentFormat, nc_coap_server_virtual_response_handler handler, void* userData)
{
    struct nc_coap_server_request* req = np_calloc(1, sizeof(struct nc_coap_server_request));
    struct nc_coap_server_virtual_request* virReq = np_calloc(1, sizeof(struct nc_coap_server_virtual_request));
    if (req == NULL || virReq == NULL || (virReq->reqPayload = np_calloc(1, payloadSize)) == NULL) {
        np_free(req);
        np_free(virReq);
        return NULL;
    }

    req->isVirtual = true;
    req->virRequest = virReq;
    req->device = ctx->device;
    virReq->method = method;
    virReq->segments = segments;
    virReq->reqPayloadSize = payloadSize;
    virReq->reqContentFormat = contentFormat;
    virReq->handler = handler;
    virReq->handlerData = userData;
    virReq->responseReady = false;
    virReq->connection = conn;
    virReq->connectionClosed = false;
    virReq->clientFreed = false;
    virReq->serverFreed = false;
    memcpy(virReq->reqPayload, payload, payloadSize);
    nn_string_map_init(&virReq->parameters, np_allocator_get());
    nc_virtual_connection_add_coap_request(conn->connectionImplCtx, req);

    struct nc_coap_server_resource* resource =  nabto_coap_server_find_resource_data(&ctx->server, method, segments, &virReq->parameters);
    if (resource == NULL) {
        virReq->serverFreed = true;
        nc_coap_server_send_error_response(req, NABTO_COAP_CODE_NOT_FOUND, "Resource not found");
    } else {
        virReq->resource = resource;
        resource->handler(req, resource->userData);
    }
    return req;
}

// Get Response data for virtual requests
int32_t nc_coap_server_response_get_content_format(struct nc_coap_server_request* request)
{
    if (!request->isVirtual ||
        request->virRequest == NULL ||
        !request->virRequest->responseReady) {
        return -1;
    } else {
        return request->virRequest->respContentFormat;
    }
}

bool nc_coap_server_response_get_payload(struct nc_coap_server_request* request, void** payload, size_t* payloadLength)
{
    if (!request->isVirtual ||
        request->virRequest == NULL ||
        !request->virRequest->responseReady) {
        return false;
    } else {
        *payload = request->virRequest->respPayload;
        *payloadLength = request->virRequest->respPayloadSize;
        return true;
    }

}

nabto_coap_code nc_coap_server_response_get_code(struct nc_coap_server_request* request)
{
    if (!request->isVirtual ||
        request->virRequest == NULL ||
        !request->virRequest->responseReady) {
        return -1;
    } else {
        return request->virRequest->respStatusCode;
    }

}
uint16_t nc_coap_server_response_get_code_human(struct nc_coap_server_request* request)
{
    if (!request->isVirtual ||
        request->virRequest == NULL ||
        !request->virRequest->responseReady) {
        return -1;
    } else {
        uint8_t compactCode = request->virRequest->respStatusCode;
        return ((compactCode >> 5)) * 100 + (compactCode & 0x1f);
    }
}

void nc_coap_server_resolve_virtual(np_error_code ec, struct nc_coap_server_request* request)
{
    request->virRequest->handler(ec, request, request->virRequest->handlerData);
}
