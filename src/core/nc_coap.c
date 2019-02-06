#include "nc_coap.h"

#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_coap_set_infinite_stamp(struct nc_coap_context* ctx);
void nc_coap_event(struct nc_coap_context* ctx);
uint32_t nc_coap_get_stamp(void* userData);
void nc_coap_notify_event(void* userData);
void nc_coap_handle_send(struct nc_coap_context* ctx);
void nc_coap_handle_wait(struct nc_coap_context* ctx);
void nc_coap_send_to_callback(const np_error_code ec, void* data);
void nc_coap_handle_timeout(const np_error_code ec, void* data);

void nc_coap_init(struct np_platform* pl, struct nc_coap_context* ctx)
{
    ctx->pl = pl;
    ctx->sendBuffer = pl->buf.allocate();
    ctx->server.getStamp = &nc_coap_get_stamp;
    ctx->server.notifyEvent = &nc_coap_notify_event;
    ctx->server.userData = ctx;
    nc_coap_set_infinite_stamp(ctx);
}

void nc_coap_handle_packet(struct nc_coap_context* ctx, struct nc_client_connection* conn,
                           np_communication_buffer* buffer, uint16_t bufferSize)
{
    nabto_coap_server_handle_packet(&ctx->server,(nabto_coap_server_connection*) nc_client_connect_get_dtls_connection(conn), ctx->pl->buf.start(buffer), bufferSize);
    nc_coap_event(ctx);
}

void nc_coap_event(struct nc_coap_context* ctx)
{
    enum nabto_coap_server_next_event nextEvent = nabto_coap_server_next_event(&ctx->server);
    NABTO_LOG_TRACE(LOG, "nc_coap_event: %u", nextEvent); 
    switch (nextEvent) {
        case NABTO_COAP_SERVER_NEXT_EVENT_SEND:
            nc_coap_handle_send(ctx);
            return;
        case NABTO_COAP_SERVER_NEXT_EVENT_WAIT:
            nc_coap_handle_wait(ctx);
            return;
        case NABTO_COAP_SERVER_NEXT_EVENT_NOTHING:
            return;
    }
    nc_coap_event(ctx);
}

void nc_coap_handle_send(struct nc_coap_context* ctx)
{
    NABTO_LOG_TRACE(LOG, "handle send");
    nabto_coap_server_connection* connection = nabto_coap_server_get_connection_send(&ctx->server);
    if (!connection) {
        nabto_coap_server_event_handled(&ctx->server, NABTO_COAP_SERVER_NEXT_EVENT_SEND);
        nc_coap_event(ctx);
        return;
    }
    np_dtls_srv_connection* dtls = (np_dtls_srv_connection*)connection;

    // Using 1400 as it is assumed to fit with the network MTU
    size_t bufferSize = 1400;
    if (ctx->pl->buf.size(ctx->sendBuffer) < bufferSize) {
        bufferSize = ctx->pl->buf.size(ctx->sendBuffer);
    }
    size_t sendSize = nabto_coap_server_handle_send(&ctx->server, ctx->pl->buf.start(ctx->sendBuffer), bufferSize);

    if (sendSize == 0) {
        nabto_coap_server_event_handled(&ctx->server, NABTO_COAP_SERVER_NEXT_EVENT_SEND);
        // nc_coap_event(ctx);
        return;
    }
    
    ctx->sendCtx.buffer = ctx->pl->buf.start(ctx->sendBuffer);
    ctx->sendCtx.bufferSize = sendSize;
    ctx->sendCtx.cb = &nc_coap_send_to_callback;
    ctx->sendCtx.data = ctx;
    ctx->pl->dtlsS.async_send_to(ctx->pl, dtls, &ctx->sendCtx);
}

void nc_coap_handle_wait(struct nc_coap_context* ctx)
{
    NABTO_LOG_TRACE(LOG, "handle wait");
    uint32_t nextStamp;
    nabto_coap_server_get_next_timeout(&ctx->server, &nextStamp);
    if (nabto_coap_is_stamp_less(nextStamp, ctx->currentExpiry)) {
        ctx->currentExpiry = nextStamp;
        uint32_t now = nabto_coap_server_stamp_now(&ctx->server);
        int32_t diff = nabto_coap_stamp_diff(nextStamp, now);
        if (diff < 0) {
            diff = 0;
        }
        np_event_queue_post_timed_event(ctx->pl, &ctx->timer, diff, &nc_coap_handle_timeout, ctx);
    }
}

void nc_coap_handle_timeout(const np_error_code ec, void* data)
{
    struct nc_coap_context* ctx = (struct nc_coap_context*) data;
    NABTO_LOG_TRACE(LOG, "Handle timeout called");
    nc_coap_set_infinite_stamp(ctx);
    nc_coap_event(ctx);
}

struct nabto_coap_server* nc_coap_get_server(struct nc_coap_context* ctx)
{
    return &ctx->server;
}

// ========= UTIL FUNCTIONS ============= //
void nc_coap_send_to_callback(const np_error_code ec, void* data)
{
    struct nc_coap_context* ctx = (struct nc_coap_context*)data;
    NABTO_LOG_TRACE(LOG, "coap_send_to_callback");
    nabto_coap_server_event_handled(&ctx->server, NABTO_COAP_SERVER_NEXT_EVENT_SEND);
    nc_coap_event(ctx);
}

uint32_t nc_coap_get_stamp(void* userData) {
    struct nc_coap_context* ctx = (struct nc_coap_context*)userData;
    return ctx->pl->ts.now_ms();
}

void nc_coap_notify_event_callback(void* userData)
{
    struct nc_coap_context* ctx = (struct nc_coap_context*)userData;
    nc_coap_event(ctx);
}

void nc_coap_notify_event(void* userData)
{
    struct nc_coap_context* ctx = (struct nc_coap_context*)userData;
    NABTO_LOG_TRACE(LOG, "nc_coap_notify_event received");
    np_event_queue_post(ctx->pl, &ctx->ev, &nc_coap_notify_event_callback, ctx);
}

void nc_coap_set_infinite_stamp(struct nc_coap_context* ctx)
{
    ctx->currentExpiry = nabto_coap_server_stamp_now(&ctx->server);
    ctx->currentExpiry += (1 << 29);
}
