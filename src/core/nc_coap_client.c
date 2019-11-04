#include "nc_coap_client.h"

#include <platform/np_logging.h>
// TODO: remove with malloc
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_coap_client_set_infinite_stamp(struct nc_coap_client_context* ctx);
void nc_coap_client_notify_event(void* userData);
void nc_coap_client_event(struct nc_coap_client_context* ctx);
void nc_coap_client_send_to_callback(const np_error_code ec, void* data);
void nc_coap_client_handle_timeout(const np_error_code ec, void* data);

struct nabto_coap_client* nc_coap_client_get_client(struct nc_coap_client_context* ctx)
{
    return &ctx->client;
}

void nc_coap_client_init(struct np_platform* pl, struct nc_coap_client_context* ctx)
{
    ctx->pl = pl;
    // TODO allocate buffer for each send.
    ctx->sendBuffer = pl->buf.allocate();
    ctx->isSending = false;
    ctx->sendCtx.buffer = pl->buf.start(ctx->sendBuffer);
    nabto_coap_client_init(&ctx->client, &nc_coap_client_notify_event, ctx);
    nc_coap_client_set_infinite_stamp(ctx);

}

void nc_coap_client_deinit(struct nc_coap_client_context* ctx)
{
    if (ctx->pl != NULL) { // if init was called
        np_event_queue_cancel_event(ctx->pl, &ctx->ev);
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->timer);
        nabto_coap_client_destroy(&ctx->client);
        ctx->pl->buf.free(ctx->sendBuffer);
    }
}

void nc_coap_client_handle_packet(struct nc_coap_client_context* ctx,
                                  uint8_t* buffer, uint16_t bufferSize, np_dtls_cli_context* dtls)
{
    enum nabto_coap_client_status status = nabto_coap_client_handle_packet(&ctx->client,
                                                                           ctx->pl->ts.now_ms(),
                                                                           buffer,
                                                                           bufferSize, dtls);
    NABTO_LOG_TRACE(LOG, "coap handling packet with status %i: ", status);
    NABTO_LOG_BUF(LOG, buffer, bufferSize);
    if (status == NABTO_COAP_CLIENT_STATUS_DECODE_ERROR) {
        // TODO log error
        NABTO_LOG_ERROR(LOG, "nabto_coap_client_handle_packet failed with status: %d", status);
    }

    nc_coap_client_event(ctx);
}

void nc_coap_client_handle_send(struct nc_coap_client_context* ctx)
{
    struct np_platform* pl = ctx->pl;
    if (ctx->isSending) {
        return;
    }

    // TODO: don't use malloc use new buffer manager
    struct np_dtls_cli_send_context* sendCtx = &ctx->sendCtx;
    uint8_t* end = sendCtx->buffer+pl->buf.size(ctx->sendBuffer);

    void* connection;
    uint8_t* ptr = nabto_coap_client_create_packet(&ctx->client, ctx->pl->ts.now_ms(), sendCtx->buffer, end, &connection);
    if (ptr == NULL || ptr < sendCtx->buffer || connection == NULL) {
        // should not happen.
    } else {
        size_t used = ptr - sendCtx->buffer;
        ctx->isSending = true;
        sendCtx->cb = &nc_coap_client_send_to_callback;
        sendCtx->data = ctx;
        sendCtx->bufferSize = used;

        np_dtls_cli_context* dtls = (np_dtls_cli_context*)connection;
        ctx->pl->dtlsC.async_send_data(ctx->pl, dtls, sendCtx);
    }
}

void nc_coap_client_handle_wait(struct nc_coap_client_context* ctx)
{
    uint32_t nextStamp;
    nextStamp = nabto_coap_client_get_next_timeout(&ctx->client, ctx->pl->ts.now_ms());
    if (nabto_coap_is_stamp_less(nextStamp, ctx->currentExpiry)) {
        ctx->currentExpiry = nextStamp;
        uint32_t now = ctx->pl->ts.now_ms();
        int32_t diff = nabto_coap_stamp_diff(nextStamp, now);
        if (diff < 0) {
            diff = 0;
        }
        np_event_queue_post_timed_event(ctx->pl, &ctx->timer, diff, &nc_coap_client_handle_timeout, ctx);
    }
}

void nc_coap_client_handle_timeout(const np_error_code ec, void* data)
{
    struct nc_coap_client_context* ctx = (struct nc_coap_client_context*) data;
    nc_coap_client_set_infinite_stamp(ctx);
    nabto_coap_client_handle_timeout(&ctx->client, ctx->pl->ts.now_ms());
    nc_coap_client_event(ctx);
}

void nc_coap_client_handle_callback(struct nc_coap_client_context* ctx)
{
    // after nabto_coap_client_handle_callback() we want to call
    // nc_coap_client_event(). However, the handle_callback can
    // resolve a coap request, and the user may alter the state, so we
    // defer calling nc_coap_client_event()
    nc_coap_client_notify_event(ctx);
    nabto_coap_client_handle_callback(&ctx->client);
//    nc_coap_client_event(ctx);
}

void nc_coap_client_event(struct nc_coap_client_context* ctx)
{
    enum nabto_coap_client_next_event nextEvent = nabto_coap_client_get_next_event(&ctx->client, ctx->pl->ts.now_ms());
    if(nextEvent == NABTO_COAP_CLIENT_NEXT_EVENT_CALLBACK) {
        nc_coap_client_handle_callback(ctx);
        return;
    } else if (nextEvent == NABTO_COAP_CLIENT_NEXT_EVENT_SEND) {
        nc_coap_client_handle_send(ctx);
        return;
    } else if (nextEvent == NABTO_COAP_CLIENT_NEXT_EVENT_WAIT) {
        nc_coap_client_handle_wait(ctx);
        return;
    } else if (nextEvent == NABTO_COAP_CLIENT_NEXT_EVENT_NOTHING) {
        return;
    }
}

// ========= UTIL FUNCTIONS ============= //

void nc_coap_client_send_to_callback(const np_error_code ec, void* data)
{
    struct nc_coap_client_context* ctx = data;
    ctx->isSending = false;
    nc_coap_client_event(ctx);
}

void nc_coap_client_notify_event_callback(void* userData)
{
    struct nc_coap_client_context* ctx = (struct nc_coap_client_context*)userData;
    nc_coap_client_event(ctx);
}

void nc_coap_client_notify_event(void* userData)
{
    struct nc_coap_client_context* ctx = (struct nc_coap_client_context*)userData;
    np_event_queue_post(ctx->pl, &ctx->ev, &nc_coap_client_notify_event_callback, ctx);
}

void nc_coap_client_set_infinite_stamp(struct nc_coap_client_context* ctx)
{
    ctx->currentExpiry = ctx->pl->ts.now_ms();
    ctx->currentExpiry += (1 << 29);
}
