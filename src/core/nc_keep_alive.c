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

void nc_keep_alive_wait(struct keep_alive_context* ctx);
enum nc_keep_alive_action nc_keep_alive_should_send(struct keep_alive_context* ctx);
void nc_keep_alive_event(const np_error_code ec, void* data);
void nc_keep_alive_send_req(struct keep_alive_context* ctx);
void nc_keep_alive_close(struct keep_alive_context* ctx, const np_error_code ec);
void nc_keep_alive_send_cb(const np_error_code ec, void* data);
void nc_keep_alive_recv(const np_error_code ec, uint8_t channelId, uint64_t seq,
                        np_communication_buffer* buf, uint16_t bufferSize, void* data);

void nc_keep_alive_init(struct np_platform* pl, struct keep_alive_context* ctx, np_dtls_cli_context* conn, keep_alive_callback cb, void* data)
{
    memset(ctx, 0, sizeof(struct keep_alive_context));
    ctx->pl = pl;
    ctx->conn = conn;
    ctx->cb = cb;
    ctx->data = data;
    ctx->buf = ctx->pl->buf.allocate();
    ctx->kaInterval = 30;
    ctx->kaRetryInterval = 2;
    ctx->kaMaxRetries = 15;
    ctx->pl->dtlsC.async_recv_from(ctx->pl, ctx->conn, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
    nc_keep_alive_wait(ctx);
    
    nc_keep_alive_send_req(ctx);
}

void nc_keep_alive_wait(struct keep_alive_context* ctx)
{
    if (ctx->lostKeepAlives == 0) {
        np_event_queue_post_timed_event(ctx->pl, &ctx->kaEv, ctx->kaInterval*1000, &nc_keep_alive_event, ctx);
    } else {
        np_event_queue_post_timed_event(ctx->pl, &ctx->kaEv, ctx->kaRetryInterval*1000, &nc_keep_alive_event, ctx);
    }
}

void nc_keep_alive_event(const np_error_code ec, void* data)
{
    struct keep_alive_context* ctx = (struct keep_alive_context*)data;
    if (ec != NABTO_EC_OK) {
        // TODO: handle error state
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

enum nc_keep_alive_action nc_keep_alive_should_send(struct keep_alive_context* ctx)
{
    uint32_t recvCount;
    uint32_t sentCount;
    np_error_code ec;
    ec = ctx->pl->dtlsC.get_packet_count(ctx->conn, &recvCount, &sentCount);
    NABTO_LOG_TRACE(LOG, "lastRecvCount: %u, recvCount: %u, LastSentCount: %u, sentCount: %u", ctx->lastRecvCount, recvCount, ctx->lastSentCount, sentCount);
    if (ec != NABTO_EC_OK) {
        nc_keep_alive_close(ctx, ec);
        return DTLS_ERROR;
    }
    if (ctx->lostKeepAlives > ctx->kaMaxRetries) {
        return KA_TIMEOUT;
    }
    if (recvCount > ctx->lastRecvCount && sentCount > ctx->lastSentCount) {
        ctx->lostKeepAlives = 0;
        ctx->lastRecvCount = recvCount;
        ctx->lastSentCount = sentCount;
        return DO_NOTHING;
    } else {
        ctx->lostKeepAlives++;
        return SEND_KA;
    }
}

void nc_keep_alive_send_req(struct keep_alive_context* ctx)
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
    ctx->pl->dtlsC.async_send_to(ctx->pl, ctx->conn, 0xff, start, 16+NABTO_PACKET_HEADER_SIZE, &nc_keep_alive_send_cb, ctx);
}

void nc_keep_alive_send_cb(const np_error_code ec, void* data)
{
    struct keep_alive_context* ctx = (struct keep_alive_context*)data;
    if(ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Keep alive received error state from DTLS: %u", ec);
        nc_keep_alive_close(ctx, ec);
        return;
    }
}

void nc_keep_alive_close(struct keep_alive_context* ctx, const np_error_code ec)
{
    NABTO_LOG_WARN(LOG, "Keep alive closing with error code: %u", ec);
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->kaEv);
    ctx->pl->dtlsC.cancel_recv_from(ctx->pl, ctx->conn, AT_KEEP_ALIVE);
    ctx->cb(ec, ctx->data);
}

void nc_keep_alive_recv(const np_error_code ec, uint8_t channelId, uint64_t seq,
                        np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    
    struct keep_alive_context* ctx = (struct keep_alive_context*)data;
    uint8_t* start = ctx->pl->buf.start(buf);
    uint8_t* ptr = start;
    NABTO_LOG_TRACE(LOG, "Received keep alive packet");
    NABTO_LOG_BUF(LOG, ctx->pl->buf.start(buf), bufferSize);
    if (ec != NABTO_EC_OK) {
        nc_keep_alive_close(ctx, ec);
        return;
    }
    ctx->pl->dtlsC.async_recv_from(ctx->pl, ctx->conn, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
}

void nc_keep_alive_stop(struct np_platform* pl,  struct keep_alive_context* ctx)
{
    nc_keep_alive_close(ctx, NABTO_EC_OK);
}

np_error_code nc_keep_alive_async_probe(struct np_platform* pl, struct keep_alive_context* ctx,
                                        uint8_t channelId, keep_alive_callback cb, void* data)
{
    return NABTO_EC_FAILED;
}
