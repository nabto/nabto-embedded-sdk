#include "nc_coap_server.h"
#include "nc_client_connection.h"
#include "nc_coap_packet_printer.h"

#include <platform/np_logging.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_coap_server_set_infinite_stamp(struct nc_coap_server_context* ctx);
void nc_coap_server_event(struct nc_coap_server_context* ctx);
uint32_t nc_coap_server_get_stamp(void* userData);
void nc_coap_server_notify_event(void* userData);
void nc_coap_server_handle_send(struct nc_coap_server_context* ctx);
void nc_coap_server_handle_wait(struct nc_coap_server_context* ctx);
void nc_coap_server_send_to_callback(const np_error_code ec, void* data);
void nc_coap_server_handle_timeout(const np_error_code ec, void* data);

np_error_code nc_coap_server_error_module_to_core(nabto_coap_error ec) {
    switch(ec) {
        case NABTO_COAP_ERROR_OK: return NABTO_EC_OK;
        case NABTO_COAP_ERROR_OUT_OF_MEMORY: return NABTO_EC_OUT_OF_MEMORY;
        case NABTO_COAP_ERROR_NO_CONNECTION: return NABTO_EC_ABORTED;
        case NABTO_COAP_ERROR_INVALID_PARAMETER: return NABTO_EC_INVALID_ARGUMENT;
        default: return NABTO_EC_UNKNOWN;
    }
}


np_error_code nc_coap_server_init(struct np_platform* pl, struct nc_coap_server_context* ctx)
{
    ctx->sendBuffer = pl->buf.allocate();
    if (!ctx->sendBuffer) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->isSending = false;
    nabto_coap_error err = nabto_coap_server_init(&ctx->server, &nc_coap_server_get_stamp, &nc_coap_server_notify_event, ctx);
    if (err != NABTO_COAP_ERROR_OK) {
        pl->buf.free(ctx->sendBuffer);
        ctx->sendBuffer = NULL;
        return nc_coap_server_error_module_to_core(err);
    }
    ctx->pl = pl;
    nc_coap_server_set_infinite_stamp(ctx);
    np_event_queue_init_event(&ctx->ev);
    return NABTO_EC_OK;
}

void nc_coap_server_deinit(struct nc_coap_server_context* ctx)
{
    if (ctx->pl != NULL) { // if init was called
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->timer);
        nabto_coap_server_destroy(&ctx->server);
        ctx->pl->buf.free(ctx->sendBuffer);
    }
}

void nc_coap_server_handle_packet(struct nc_coap_server_context* ctx, struct nc_client_connection* conn,
                                  uint8_t* buffer, uint16_t bufferSize)
{
    nc_coap_packet_print("coap server handle packet", buffer, bufferSize);
    nabto_coap_server_handle_packet(&ctx->server,(void*) conn, buffer, bufferSize);
    nc_coap_server_event(ctx);
}

void nc_coap_server_event(struct nc_coap_server_context* ctx)
{
    enum nabto_coap_server_next_event nextEvent = nabto_coap_server_next_event(&ctx->server);
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

    if (ctx->isSending) {
        //NABTO_LOG_TRACE(LOG, "handle send, isSending: %i", ctx->isSending );
        return;
    }

    void* connection = nabto_coap_server_get_connection_send(&ctx->server);
    if (!connection) {
        nc_coap_server_event(ctx);
        return;
    }
    struct nc_client_connection* clientConnection = (struct nc_client_connection*)connection;
    np_dtls_srv_connection* dtls = clientConnection->dtls;

    uint8_t* sendBuffer = pl->buf.start(ctx->sendBuffer);
    size_t sendBufferSize = pl->buf.size(ctx->sendBuffer);

    uint8_t* sendEnd = nabto_coap_server_handle_send(&ctx->server, sendBuffer, sendBuffer + sendBufferSize);

    if (sendEnd == NULL || sendEnd < sendBuffer) {
        // this should not happen
        nc_coap_server_event(ctx);
        return;
    }

//    sendCtx->dtls.buffer = ctx->pl->buf.start(ctx->sendBuffer);
    struct np_dtls_srv_send_context* sendCtx = &ctx->sendCtx;
    sendCtx->buffer = sendBuffer;
    sendCtx->bufferSize = sendEnd - sendBuffer;
    sendCtx->cb = &nc_coap_server_send_to_callback;
    sendCtx->data = ctx;
    sendCtx->channelId = NP_DTLS_SRV_DEFAULT_CHANNEL_ID;
    ctx->isSending = true;
    nc_coap_packet_print("coap server send packet", sendCtx->buffer, sendCtx->bufferSize);
    ctx->pl->dtlsS.async_send_data(ctx->pl, dtls, sendCtx);
}

void nc_coap_server_handle_wait(struct nc_coap_server_context* ctx)
{
    uint32_t nextStamp;
    nabto_coap_server_get_next_timeout(&ctx->server, &nextStamp);
    if (nabto_coap_is_stamp_less(nextStamp, ctx->currentExpiry)) {
        ctx->currentExpiry = nextStamp;
        uint32_t now = nabto_coap_server_stamp_now(&ctx->server);
        int32_t diff = nabto_coap_stamp_diff(nextStamp, now);
        if (diff < 0) {
            diff = 0;
        }
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->timer);
        np_event_queue_post_timed_event(ctx->pl, &ctx->timer, diff, &nc_coap_server_handle_timeout, ctx);
    }
}

void nc_coap_server_handle_timeout(const np_error_code ec, void* data)
{
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*) data;
    //NABTO_LOG_TRACE(LOG, "Handle timeout called");
    nc_coap_server_set_infinite_stamp(ctx);
    nabto_coap_server_handle_timeout(&ctx->server);
    nc_coap_server_event(ctx);
}

struct nabto_coap_server* nc_coap_server_get_server(struct nc_coap_server_context* ctx)
{
    return &ctx->server;
}

void nc_coap_server_context_request_get_connection_id(struct nc_coap_server_context* ctx, struct nabto_coap_server_request* request, uint8_t* connectionId)
{
    struct nc_client_connection* conn = (struct nc_client_connection*)nabto_coap_server_request_get_connection(request);
    memcpy(connectionId, conn->id.id+1, 14);

}

struct nc_client_connection* nc_coap_server_get_connection(struct nc_coap_server_context* ctx, struct nabto_coap_server_request* request)
{
    return (struct nc_client_connection*)nabto_coap_server_request_get_connection(request);
}

void nc_coap_server_remove_connection(struct nc_coap_server_context* ctx, struct nc_client_connection* connection)
{
    nabto_coap_server_remove_connection(&ctx->server, (void*) connection);
}

// ========= UTIL FUNCTIONS ============= //
void nc_coap_server_send_to_callback(const np_error_code ec, void* data)
{
    struct nc_coap_server_context* ctx = data;
    ctx->isSending = false;
    nc_coap_server_event(ctx);
}

uint32_t nc_coap_server_get_stamp(void* userData) {
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*)userData;
    return ctx->pl->ts.now_ms();
}

void nc_coap_server_notify_event_callback(void* userData)
{
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*)userData;
    nc_coap_server_event(ctx);
}

void nc_coap_server_notify_event(void* userData)
{
    struct nc_coap_server_context* ctx = (struct nc_coap_server_context*)userData;
    np_event_queue_post_maybe_double(ctx->pl, &ctx->ev, &nc_coap_server_notify_event_callback, ctx);
}

void nc_coap_server_set_infinite_stamp(struct nc_coap_server_context* ctx)
{
    ctx->currentExpiry = nabto_coap_server_stamp_now(&ctx->server);
    ctx->currentExpiry += (1 << 29);
}
