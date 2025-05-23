#include "nc_coap_client.h"

#include <core/nc_coap.h>

#include <platform/np_allocator.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_logging.h>
#include <platform/np_timestamp_wrapper.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_coap_client_set_infinite_stamp(struct nc_coap_client_context* ctx);
void nc_coap_client_notify_event(void* userData);
static void nc_coap_client_event_deferred(struct nc_coap_client_context* ctx);
void nc_coap_client_event(struct nc_coap_client_context* ctx);
void nc_coap_client_send_to_callback(const np_error_code ec, void* data);
void nc_coap_client_handle_timeout(void* data);

static void nc_coap_client_notify_event_callback(void* userData);

struct nabto_coap_client* nc_coap_client_get_client(struct nc_coap_client_context* ctx)
{
    return &ctx->client;
}

np_error_code nc_coap_client_init(struct np_platform* pl, struct nc_coap_client_context* ctx)
{
    ctx->sendBuffer = NULL;
    ctx->pl = pl;
    np_error_code ec = np_event_queue_create_event(&ctx->pl->eq, &nc_coap_client_notify_event_callback, ctx, &ctx->ev);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_event_queue_create_event(&ctx->pl->eq, &nc_coap_client_handle_timeout, ctx, &ctx->timer);
    if (ec != NABTO_EC_OK)
    {
        return ec;
    }

    ec = np_completion_event_init(&ctx->pl->eq, &ctx->sendCtx.ev,
                                  &nc_coap_client_send_to_callback, ctx);
    if (ec != NABTO_EC_OK)
    {
        return ec;
    }

    nabto_coap_error err = nabto_coap_client_init(&ctx->client, np_allocator_get(), &nc_coap_client_notify_event, ctx);
    if (err != NABTO_COAP_ERROR_OK) {
        return nc_coap_error_to_core(err);
    }
    nc_coap_client_set_infinite_stamp(ctx);

    return NABTO_EC_OK;
}

void nc_coap_client_deinit(struct nc_coap_client_context* ctx)
{
    if (ctx->pl != NULL) { // if init was called
        struct np_event_queue* eq = &ctx->pl->eq;
        np_event_queue_destroy_event(eq, ctx->ev);
        np_event_queue_destroy_event(eq, ctx->timer);
        np_completion_event_deinit(&ctx->sendCtx.ev);
        nabto_coap_client_destroy(&ctx->client);
    }
}

void nc_coap_client_stop(struct nc_coap_client_context* ctx)
{
    struct np_event_queue* eq = &ctx->pl->eq;
    nabto_coap_client_stop(&ctx->client);
    nc_coap_client_event(ctx);
    np_event_queue_cancel_event(eq, ctx->timer);
}

void nc_coap_client_handle_packet(struct nc_coap_client_context* ctx,
                                  uint8_t* buffer, uint16_t bufferSize, struct np_dtls_cli_connection* dtls)
{
    uint32_t ts = np_timestamp_now_ms(&ctx->pl->timestamp);
    enum nabto_coap_client_status status = nabto_coap_client_handle_packet(&ctx->client,
                                                                           ts,
                                                                           buffer,
                                                                           bufferSize, dtls);
    NABTO_LOG_TRACE(LOG, "coap handling packet with status %i: ", status);
    if (status == NABTO_COAP_CLIENT_STATUS_DECODE_ERROR) {
        NABTO_LOG_ERROR(LOG, "nabto_coap_client_handle_packet failed with status: %d", status);
    }

    nc_coap_client_event(ctx);
}

np_error_code nc_coap_client_handle_send(struct nc_coap_client_context* ctx)
{
    struct np_platform* pl = ctx->pl;
    if (ctx->sendBuffer != NULL) {
        // already sending.
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    uint32_t ts = np_timestamp_now_ms(&ctx->pl->timestamp);
    void* connection = NULL;

    ctx->sendBuffer = pl->buf.allocate();
    if (ctx->sendBuffer == NULL) {
        // discard the packet
        nabto_coap_client_create_packet(&ctx->client, ts, NULL, NULL, &connection);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    struct np_dtls_send_context* sendCtx = &ctx->sendCtx;
    sendCtx->buffer = pl->buf.start(ctx->sendBuffer);

    uint8_t* end = sendCtx->buffer+pl->buf.size(ctx->sendBuffer);

    uint8_t* ptr = nabto_coap_client_create_packet(&ctx->client, ts, sendCtx->buffer, end, &connection);
    if (ptr == NULL || ptr < sendCtx->buffer || connection == NULL) {
        // should not happen.
        pl->buf.free(ctx->sendBuffer);
        ctx->sendBuffer = NULL;
        return NABTO_EC_UNKNOWN;
    }
    size_t used = ptr - sendCtx->buffer;
    sendCtx->bufferSize = (uint16_t)used;

    struct np_dtls_cli_connection* dtls = connection;
    ctx->pl->dtlsC.async_send_data(dtls, sendCtx);
    return NABTO_EC_OPERATION_STARTED;
}

void nc_coap_client_handle_wait(struct nc_coap_client_context* ctx)
{
    uint32_t nextStamp = 0;
    uint32_t now = np_timestamp_now_ms(&ctx->pl->timestamp);
    nextStamp = nabto_coap_client_get_next_timeout(&ctx->client, now);
    if (nabto_coap_is_stamp_less(nextStamp, ctx->currentExpiry)) {
        ctx->currentExpiry = nextStamp;
        int32_t diff = nabto_coap_stamp_diff(nextStamp, now);
        if (diff < 0) {
            diff = 0;
        }
        np_event_queue_post_timed_event(&ctx->pl->eq, ctx->timer, diff);
    }
}

void nc_coap_client_handle_timeout(void* data)
{
    struct nc_coap_client_context* ctx = (struct nc_coap_client_context*) data;
    nc_coap_client_set_infinite_stamp(ctx);
    uint32_t now = np_timestamp_now_ms(&ctx->pl->timestamp);
    nabto_coap_client_handle_timeout(&ctx->client, now);
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
    uint32_t now = np_timestamp_now_ms(&ctx->pl->timestamp);
    enum nabto_coap_client_next_event nextEvent =
        nabto_coap_client_get_next_event(&ctx->client, now);
    if (nextEvent == NABTO_COAP_CLIENT_NEXT_EVENT_CALLBACK) {
        nc_coap_client_handle_callback(ctx);
        return;
    }
    if (nextEvent == NABTO_COAP_CLIENT_NEXT_EVENT_SEND) {
        np_error_code ec = nc_coap_client_handle_send(ctx);
        if (ec == NABTO_EC_OPERATION_IN_PROGRESS ||
            ec == NABTO_EC_OPERATION_STARTED) {
            return;
        }
        // a packet was not sent,
        nc_coap_client_event_deferred(ctx);
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
    (void)ec;
    struct nc_coap_client_context* ctx = data;
    ctx->pl->buf.free(ctx->sendBuffer);
    ctx->sendBuffer = NULL;
    nc_coap_client_event(ctx);
}

void nc_coap_client_notify_event_callback(void* userData)
{
    struct nc_coap_client_context* ctx = (struct nc_coap_client_context*)userData;
    nc_coap_client_event(ctx);
}

void nc_coap_client_event_deferred(struct nc_coap_client_context* ctx)
{
    np_event_queue_post_maybe_double(&ctx->pl->eq, ctx->ev);
}

void nc_coap_client_notify_event(void* userData)
{
    struct nc_coap_client_context* ctx = (struct nc_coap_client_context*)userData;
    nc_coap_client_event_deferred(ctx);
}

void nc_coap_client_set_infinite_stamp(struct nc_coap_client_context* ctx)
{
    uint32_t now = np_timestamp_now_ms(&ctx->pl->timestamp);
    ctx->currentExpiry = now;
    // overflow is welldefined for unsigned integers in the c standard.
    ctx->currentExpiry += (1 << 29);
}
