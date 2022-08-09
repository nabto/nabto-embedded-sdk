#include "nc_coap_server.h"
#include "nc_coap.h"
#include "nc_client_connection.h"
#include "nc_coap_packet_printer.h"

#include <platform/np_logging.h>
#include <platform/np_timestamp_wrapper.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_allocator.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_coap_server_set_infinite_stamp(struct nc_coap_server_context* ctx);
void nc_coap_server_event(struct nc_coap_server_context* ctx);
uint32_t nc_coap_server_get_stamp(void* userData);
void nc_coap_server_notify_event(void* userData);
void nc_coap_server_handle_send(struct nc_coap_server_context* ctx);
void nc_coap_server_handle_wait(struct nc_coap_server_context* ctx);
void nc_coap_server_send_to_callback(const np_error_code ec, void* data);
void nc_coap_server_handle_timeout(void* data);

static void nc_coap_server_notify_event_callback(void* userData);

np_error_code nc_coap_server_init(struct np_platform* pl, struct nn_log* logger, struct nc_coap_server_context* ctx)
{
    ctx->sendBuffer = NULL;
    nabto_coap_error err = nabto_coap_server_init(&ctx->server, logger, np_allocator_get());
    nabto_coap_server_requests_init(&ctx->requests, &ctx->server, &nc_coap_server_get_stamp, &nc_coap_server_notify_event, ctx);
    if (err != NABTO_COAP_ERROR_OK) {
        return nc_coap_error_to_core(err);
    }
    ctx->pl = pl;
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
    nc_coap_packet_print("coap server handle packet", buffer, bufferSize);
    nabto_coap_server_handle_packet(&ctx->requests,(void*) conn, buffer, bufferSize);
    nc_coap_server_event(ctx);
}

void nc_coap_server_event(struct nc_coap_server_context* ctx)
{
    enum nabto_coap_server_next_event nextEvent = nabto_coap_server_next_event(&ctx->requests);
    switch (nextEvent) {
        case NABTO_COAP_SERVER_NEXT_EVENT_SEND:
            nc_coap_server_handle_send(ctx);
            return;
        case NABTO_COAP_SERVER_NEXT_EVENT_WAIT:
            nc_coap_server_handle_wait(ctx);
            return;
        case NABTO_COAP_SERVER_NEXT_EVENT_NOTHING:
            return;
    }
    //nc_coap_server_event(ctx);
}

void nc_coap_server_handle_send(struct nc_coap_server_context* ctx)
{
    struct np_platform* pl = ctx->pl;

    if (ctx->sendBuffer != NULL) {
        //NABTO_LOG_TRACE(LOG, "handle send, isSending: %i", ctx->isSending );
        return;
    }

    void* connection = nabto_coap_server_get_connection_send(&ctx->requests);
    if (!connection) {
        nc_coap_server_event(ctx);
        return;
    }
    struct nc_client_connection* clientConnection = (struct nc_client_connection*)connection;

    ctx->sendBuffer = pl->buf.allocate();
    if (ctx->sendBuffer == NULL) {
        NABTO_LOG_ERROR(LOG, "canot allocate buffer for sending a packet from the coap server.");
        return;
    }
    uint8_t* sendBuffer = pl->buf.start(ctx->sendBuffer);
    size_t sendBufferSize = pl->buf.size(ctx->sendBuffer);

    uint8_t* sendEnd = nabto_coap_server_handle_send(&ctx->requests, sendBuffer, sendBuffer + sendBufferSize);

    if (sendEnd == NULL || sendEnd < sendBuffer) {
        // this should not happen
        nc_coap_server_event(ctx);
        pl->buf.free(ctx->sendBuffer);
        ctx->sendBuffer = NULL;
        return;
    }

    struct np_dtls_cli_send_context* sendCtx = &ctx->sendCtx;
    sendCtx->buffer = sendBuffer;
    sendCtx->bufferSize = (uint16_t)(sendEnd - sendBuffer);
    sendCtx->channelId = NP_DTLS_CLI_DEFAULT_CHANNEL_ID;
    nc_coap_packet_print("coap server send packet", sendCtx->buffer, sendCtx->bufferSize);
    nc_client_connection_async_send_data(clientConnection, sendCtx);
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

struct nabto_coap_server* nc_coap_server_get_server(struct nc_coap_server_context* ctx)
{
    return &ctx->server;
}

void nc_coap_server_context_request_get_connection_id(struct nc_coap_server_context* ctx, struct nabto_coap_server_request* request, uint8_t* connectionId)
{
    (void)ctx;
    struct nc_client_connection* conn = (struct nc_client_connection*)nabto_coap_server_request_get_connection(request);
    memcpy(connectionId, conn->id.id+1, 14);

}

struct nc_client_connection* nc_coap_server_get_connection(struct nc_coap_server_context* ctx, struct nabto_coap_server_request* request)
{
    (void)ctx;
    return (struct nc_client_connection*)nabto_coap_server_request_get_connection(request);
}

void nc_coap_server_remove_connection(struct nc_coap_server_context* ctx, struct nc_client_connection* connection)
{
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

void nc_coap_server_notify_event(void* userData)
{
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*)userData;
    np_event_queue_post_maybe_double(&ctx->pl->eq, ctx->ev);
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
