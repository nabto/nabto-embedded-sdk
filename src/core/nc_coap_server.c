#include "nc_coap_server.h"
#include "nc_coap.h"
#include "nc_client_connection.h"
#include "nc_connection.h"
#include "nc_coap_packet_printer.h"
#include "nc_device.h"

#include <platform/np_logging.h>
#include <platform/np_timestamp_wrapper.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_allocator.h>

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
    struct nc_client_connection* conn = (struct nc_client_connection*)nabto_coap_server_request_get_connection(request->request);
    memcpy(connectionId, conn->id.id+1, 14);
    return true;
}

void nc_coap_server_remove_connection(struct nc_coap_server_context* ctx, struct nc_client_connection* connection)
{
    NABTO_LOG_TRACE(LOG, "Removing connection from coap server.");
    nabto_coap_server_remove_connection(&ctx->requests, (void*) connection);
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
    nabto_coap_server_limit_requests(&ctx->requests, limit);
}


void resource_callback(struct nabto_coap_server_request* request, void* userData)
{
    struct nc_coap_server_resource* res = (struct nc_coap_server_resource*)userData;
    struct nc_coap_server_request* req = np_calloc(1, sizeof(struct nc_coap_server_request));
    req->request = request;
    req->device = res->device;
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
    return nabto_coap_server_add_resource(&server->server, method, segments, &resource_callback, *resource, &(*resource)->resource);
}

void nc_coap_server_remove_resource(struct nc_coap_server_resource* resource)
{
    nabto_coap_server_remove_resource(resource->resource);
    np_free(resource);
}

nabto_coap_error nc_coap_server_send_error_response(struct nc_coap_server_request* request, nabto_coap_code status, const char* description)
{
    return nabto_coap_server_send_error_response(request->request, status, description);
}

void nc_coap_server_response_set_code(struct nc_coap_server_request* request, nabto_coap_code code)
{
    return nabto_coap_server_response_set_code(request->request, code);
}
void nc_coap_server_response_set_code_human(struct nc_coap_server_request* request, uint16_t humanCode)
{
    return nabto_coap_server_response_set_code_human(request->request, humanCode);
}

nabto_coap_error nc_coap_server_response_set_payload(struct nc_coap_server_request* request, const void* data, size_t dataSize)
{
    return nabto_coap_server_response_set_payload(request->request, data, dataSize);
}

void nc_coap_server_response_set_content_format(struct nc_coap_server_request* request, uint16_t format)
{
    return nabto_coap_server_response_set_content_format(request->request, format);
}

nabto_coap_error nc_coap_server_response_ready(struct nc_coap_server_request* request)
{
    return nabto_coap_server_response_ready(request->request);
}

void nc_coap_server_request_free(struct nc_coap_server_request* request)
{
    nabto_coap_server_request_free(request->request);
    np_free(request);
}

/**
 * Get content format, if no content format is present return -1 else
 * a contentFormat between 0 and 2^16-1 is returned.
 */
int32_t nc_coap_server_request_get_content_format(struct nc_coap_server_request* request)
{
    return nabto_coap_server_request_get_content_format(request->request);
}

bool nc_coap_server_request_get_payload(struct nc_coap_server_request* request, void** payload, size_t* payloadLength)
{
    return nabto_coap_server_request_get_payload(request->request,payload, payloadLength);
}

void* nc_coap_server_request_get_connection(struct nc_coap_server_request* request)
{
    struct nc_client_connection* cliConn = nabto_coap_server_request_get_connection(request->request);
    return nc_connections_connection_from_client_connection(&request->device->connections, cliConn);
}

uint64_t nc_coap_server_request_get_connection_ref(struct nc_coap_server_request* request)
{
    struct nc_client_connection* cliConn = (struct nc_client_connection*)nabto_coap_server_request_get_connection(request->request);
    struct nc_connection* connection = nc_connections_connection_from_client_connection(&request->device->connections, cliConn);
    if (connection != NULL) {
        return connection->connectionRef;
    }
    return 0;
}

const char* nc_coap_server_request_get_parameter(struct nc_coap_server_request* request, const char* parameter)
{
    return nabto_coap_server_request_get_parameter(request->request, parameter);
}
