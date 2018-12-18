#include "nc_keep_alive.h"
#include <platform/np_event_queue.h>
#include <platform/np_logging.h>
#include <core/nc_packet.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_KEEP_ALIVE


enum nc_keep_alive_action{
    DO_NOTHING,
    SEND_KA,
    KA_TIMEOUT,
    DTLS_ERROR
};

void nc_keep_alive_wait(struct nc_keep_alive_context* ctx);
enum nc_keep_alive_action nc_keep_alive_should_send(struct nc_keep_alive_context* ctx);
void nc_keep_alive_event(const np_error_code ec, void* data);
void nc_keep_alive_send_req(struct nc_keep_alive_context* ctx);
void nc_keep_alive_close(struct nc_keep_alive_context* ctx, const np_error_code ec);
void nc_keep_alive_send_cb(const np_error_code ec, void* data);
void nc_keep_alive_recv(const np_error_code ec, uint8_t channelId, uint64_t seq,
                        np_communication_buffer* buf, uint16_t bufferSize, void* data);

void nc_keep_alive_init_cli(struct np_platform* pl, struct nc_keep_alive_context* ctx, np_dtls_cli_context* conn, keep_alive_callback cb, void* data)
{
    memset(ctx, 0, sizeof(struct nc_keep_alive_context));
    ctx->pl = pl;
    ctx->buf = ctx->pl->buf.allocate();
    ctx->isCli = true;
    ctx->cli = conn;
    ctx->cb = cb;
    ctx->data = data;
}

void nc_keep_alive_init_srv(struct np_platform* pl, struct nc_keep_alive_context* ctx, struct np_dtls_srv_connection* conn, keep_alive_callback cb, void* data)
{
    memset(ctx, 0, sizeof(struct nc_keep_alive_context));
    ctx->pl = pl;
    ctx->buf = ctx->pl->buf.allocate();
    ctx->isCli = false;
    ctx->srv = conn;
    ctx->cb = cb;
    ctx->data = data;
}

np_error_code nc_keep_alive_start(struct np_platform* pl, struct nc_keep_alive_context* ctx, uint32_t interval, uint8_t retryInterval, uint8_t maxRetries)
{
    NABTO_LOG_TRACE(LOG, "starting keep alive with interval: %u, retryInt: %u, maxRetries: %u", interval, retryInterval, maxRetries);
    if (pl != ctx->pl) {
        // either uninitialized or changed platform
        return NABTO_EC_FAILED;
    }
    ctx->kaInterval = interval;
    ctx->kaRetryInterval = retryInterval;
    ctx->kaMaxRetries = maxRetries;
    ctx->n = ctx->kaInterval/ctx->kaRetryInterval/1000;
    if (ctx->isCli) {
        ctx->pl->dtlsC.async_recv_from(ctx->pl, ctx->cli, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
    } else {
        ctx->pl->dtlsS.async_recv_from(ctx->pl, ctx->srv, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
    }
    nc_keep_alive_wait(ctx);
    return NABTO_EC_OK;
}

void nc_keep_alive_wait(struct nc_keep_alive_context* ctx)
{
    np_event_queue_post_timed_event(ctx->pl, &ctx->kaEv, ctx->kaRetryInterval*1000, &nc_keep_alive_event, ctx);
}

void nc_keep_alive_event(const np_error_code ec, void* data)
{
    struct nc_keep_alive_context* ctx = (struct nc_keep_alive_context*)data;
    if (ec != NABTO_EC_OK) {
        nc_keep_alive_close(ctx, ec);
    } else {
        enum nc_keep_alive_action action = nc_keep_alive_should_send(ctx);
        switch(action) {
            case DO_NOTHING:
                nc_keep_alive_wait(ctx);
                break;
            case SEND_KA:
                nc_keep_alive_send_req(ctx);
                nc_keep_alive_wait(ctx);
                break;
            case KA_TIMEOUT:
                nc_keep_alive_close(ctx, NABTO_EC_KEEP_ALIVE_TIMEOUT);
                break;
            case DTLS_ERROR:
                return;
        }
    }
}

enum nc_keep_alive_action nc_keep_alive_should_send(struct nc_keep_alive_context* ctx)
{
    uint32_t recvCount;
    uint32_t sentCount;
    np_error_code ec;
    if(ctx->isCli) {
        ec = ctx->pl->dtlsC.get_packet_count(ctx->cli, &recvCount, &sentCount);
    } else {
        ec = ctx->pl->dtlsS.get_packet_count(ctx->srv, &recvCount, &sentCount);
    }
    NABTO_LOG_TRACE(LOG, "lastRecvCount: %u, recvCount: %u, LastSentCount: %u, sentCount: %u", ctx->lastRecvCount, recvCount, ctx->lastSentCount, sentCount);
    if (ec != NABTO_EC_OK) {
        nc_keep_alive_close(ctx, ec);
        return DTLS_ERROR;
    }
    if (ctx->lostKeepAlives > ctx->kaMaxRetries+ctx->n) {
        return KA_TIMEOUT;
    }
    if (recvCount > ctx->lastRecvCount && sentCount > ctx->lastSentCount) {
        ctx->lostKeepAlives = 0;
        ctx->lastRecvCount = recvCount;
        ctx->lastSentCount = sentCount;
        return DO_NOTHING;
    } else {
        ctx->lostKeepAlives++;
        if(ctx->lostKeepAlives > ctx->n) {
            return SEND_KA;
        } else {
            return DO_NOTHING;
        }
    }
}

void nc_keep_alive_send_req(struct nc_keep_alive_context* ctx)
{
    uint8_t* start = ctx->pl->buf.start(ctx->buf);
    uint8_t buf[16];
    int i = 0;
    start[0] = (enum application_data_type)AT_KEEP_ALIVE;
    start[1] = (enum keep_alive_content_type)CT_KEEP_ALIVE_REQUEST;
    for (i = 0; i < 16; i++) {
        *(start+2+i) = i;
    }
    NABTO_LOG_TRACE(LOG, "Sending keep alive request: ");
    NABTO_LOG_BUF(LOG, start, 16+NABTO_PACKET_HEADER_SIZE);
    if(ctx->isCli) {
        ctx->pl->dtlsC.async_send_to(ctx->pl, ctx->cli, 0xff, start, 16+NABTO_PACKET_HEADER_SIZE, &nc_keep_alive_send_cb, ctx);
    } else {
        ctx->pl->dtlsS.async_send_to(ctx->pl, ctx->srv, start, 16+NABTO_PACKET_HEADER_SIZE, &nc_keep_alive_send_cb, ctx);
    }
}

void nc_keep_alive_send_cb(const np_error_code ec, void* data)
{
    struct nc_keep_alive_context* ctx = (struct nc_keep_alive_context*)data;
    if(ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Keep alive received error state from DTLS: %u", ec);
        nc_keep_alive_close(ctx, ec);
        return;
    }
}

void nc_keep_alive_close(struct nc_keep_alive_context* ctx, const np_error_code ec)
{
    NABTO_LOG_WARN(LOG, "Keep alive closing with error code: %u", ec);
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->kaEv);
    if(ctx->isCli) {
        ctx->pl->dtlsC.cancel_recv_from(ctx->pl, ctx->cli, AT_KEEP_ALIVE);
    } else {
        ctx->pl->dtlsS.cancel_recv_from(ctx->pl, ctx->srv, AT_KEEP_ALIVE);
    }
    ctx->cb(ec, ctx->data);
}

void nc_keep_alive_recv(const np_error_code ec, uint8_t channelId, uint64_t seq,
                        np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    
    struct nc_keep_alive_context* ctx = (struct nc_keep_alive_context*)data;
    if (ec != NABTO_EC_OK) {
        nc_keep_alive_close(ctx, ec);
        return;
    }
    NABTO_LOG_TRACE(LOG, "Received keep alive packet");
    NABTO_LOG_BUF(LOG, ctx->pl->buf.start(buf), bufferSize);
    if(ctx->isCli) {
        ctx->pl->dtlsC.async_recv_from(ctx->pl, ctx->cli, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
    } else {
        ctx->pl->dtlsS.async_recv_from(ctx->pl, ctx->srv, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
    } 
}

void nc_keep_alive_stop(struct np_platform* pl,  struct nc_keep_alive_context* ctx)
{
    nc_keep_alive_close(ctx, NABTO_EC_OK);
}

np_error_code nc_keep_alive_async_probe(struct np_platform* pl, struct nc_keep_alive_context* ctx,
                                        uint8_t channelId, keep_alive_callback cb, void* data)
{
    return NABTO_EC_FAILED;
}
