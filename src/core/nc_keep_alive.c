#include "nc_keep_alive.h"
#include <platform/np_event_queue.h>
#include <platform/np_logging.h>
#include <core/nc_packet.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_KEEP_ALIVE

void nc_keep_alive_send_cb(const np_error_code ec, void* data);
void nc_keep_alive_send_res_cb(const np_error_code ec, void* data);
void nc_keep_alive_retrans_event(const np_error_code ec, void* data);
void nc_keep_alive_recv(const np_error_code ec, uint8_t channelId, uint64_t seq,
                        np_communication_buffer* buf, uint16_t bufferSize, void* data);

void nc_keep_alive_send_req(struct keep_alive_context* ctx)
{
    uint8_t* ptr;
    uint8_t* start = ctx->pl->buf.start(ctx->buf);
    uint8_t buf[16];
    start[0] = (enum application_data_type)AT_KEEP_ALIVE;
    start[1] = (enum keep_alive_content_type)CT_KEEP_ALIVE_REQUEST;
    memcpy(buf, &ctx->sequence, 2);
    memset(buf+2, 0, 14);
    ptr = insert_packet_extension(ctx->pl, start+NABTO_PACKET_HEADER_SIZE, EX_KEEP_ALIVE, buf, 16);
    NABTO_LOG_TRACE(LOG, "keep alive request to send: ");
    NABTO_LOG_BUF(LOG, start, ptr-start);
    ctx->pl->dtlsC.async_send_to(ctx->pl, ctx->conn, 0xff, start, ptr - start, &nc_keep_alive_send_cb, ctx);
;
}

void nc_keep_alive_send_res(struct keep_alive_context* ctx, uint8_t channelId, np_communication_buffer* buffer, uint16_t bufferSize)
{
    uint8_t* ptr = ctx->pl->buf.start(buffer);
    uint8_t* start = ctx->pl->buf.start(ctx->buf);
    start[0] = (enum application_data_type)AT_KEEP_ALIVE;
    start[1] = (enum keep_alive_content_type)CT_KEEP_ALIVE_RESPONSE;
    if(bufferSize < NABTO_PACKET_HEADER_SIZE + 16) {
        NABTO_LOG_ERROR(LOG, "Received keep alive request of insufficient size");
        return;
    }
    memcpy(start + NABTO_PACKET_HEADER_SIZE, ptr + NABTO_PACKET_HEADER_SIZE, 16);
    ctx->pl->dtlsC.async_send_to(ctx->pl, ctx->conn, channelId, start, ptr - start, &nc_keep_alive_send_res_cb, ctx);
;
}

void nc_keep_alive_retrans_event(const np_error_code ec, void* data)
{
    struct keep_alive_context* ctx = (struct keep_alive_context*)data;
    if(ctx->currentRetry >= ctx->kaMaxRetries) {
        NABTO_LOG_ERROR(LOG, "Keep alive failed: Too many keep alive retransmissions");
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->kaEv);
        ctx->pl->dtlsC.cancel_recv_from(ctx->pl, ctx->conn, AT_KEEP_ALIVE);
        ctx->cb(NABTO_EC_FAILED, ctx->data);
        return;
    }
    nc_keep_alive_send_req(ctx);
    np_event_queue_post_timed_event(ctx->pl, &ctx->kaEv, ctx->kaRetryInterval*1000, &nc_keep_alive_retrans_event, ctx);
    ctx->currentRetry++;
}

void nc_keep_alive_ka_event(const np_error_code ec, void* data)
{
    struct keep_alive_context* ctx = (struct keep_alive_context*)data;
    nc_keep_alive_send_req(ctx);
    np_event_queue_post_timed_event(ctx->pl, &ctx->kaEv, ctx->kaInterval*1000, &nc_keep_alive_ka_event, ctx);
}

void nc_keep_alive_send_cb(const np_error_code ec, void* data)
{
    struct keep_alive_context* ctx = (struct keep_alive_context*)data;
    if(ec != NABTO_EC_OK) {
        np_event_queue_cancel_timed_event(ctx->pl, &ctx->kaEv);
        ctx->pl->dtlsC.cancel_recv_from(ctx->pl, ctx->conn, AT_KEEP_ALIVE);
        ctx->cb(ec, ctx->data);
        return;
    }
}


void nc_keep_alive_init(struct np_platform* pl, struct keep_alive_context* ctx, np_dtls_cli_context* conn, keep_alive_callback cb, void* data)
{
    ctx->pl = pl;
    ctx->conn = conn;
    ctx->cb = cb;
    ctx->data = data;
    ctx->buf = ctx->pl->buf.allocate();
    ctx->kaInterval = 10;
    ctx->kaRetryInterval = 1;
    ctx->kaMaxRetries = 5;
    ctx->currentRetry = 0;
    ctx->sequence = 0;
    ctx->pl->dtlsC.async_recv_from(ctx->pl, ctx->conn, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
    nc_keep_alive_send_req(ctx);
    np_event_queue_post_timed_event(ctx->pl, &ctx->kaEv, ctx->kaRetryInterval, &nc_keep_alive_retrans_event, ctx);
}

void nc_keep_alive_stop(struct np_platform* pl,  struct keep_alive_context* ctx)
{
    ctx->pl->dtlsC.cancel_recv_from(ctx->pl, ctx->conn, AT_KEEP_ALIVE);
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->kaEv);
    ctx->cb(NABTO_EC_OK, ctx->data);
}

void nc_keep_alive_decode_res(struct keep_alive_context* ctx, np_communication_buffer* buf, uint16_t bufSize)
{
    // TODO: for now assuming response is from correct sequence number if not check probe ctx
    // cancelling retry event
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->kaEv);
    ctx->sequence++;
    // scheduling next keep alive 
    np_event_queue_post_timed_event(ctx->pl, &ctx->kaEv, ctx->kaInterval, &nc_keep_alive_ka_event, ctx);
}

void nc_keep_alive_recv(const np_error_code ec, uint8_t channelId, uint64_t seq,
                        np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    
    struct keep_alive_context* ctx = (struct keep_alive_context*)data;
    uint8_t* start = ctx->pl->buf.start(buf);
    uint8_t* ptr = start;
    NABTO_LOG_TRACE(LOG, "Received keep alive packet");
    NABTO_LOG_BUF(LOG, ctx->pl->buf.start(buf), bufferSize);
    ctx->pl->dtlsC.async_recv_from(ctx->pl, ctx->conn, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
    if ((enum application_data_type)start[0] == AT_KEEP_ALIVE) {
        if ((enum keep_alive_content_type)start[1] == CT_KEEP_ALIVE_REQUEST) {
            nc_keep_alive_send_res(ctx, channelId, buf, bufferSize);
        } else if ((enum keep_alive_content_type)start[1] == CT_KEEP_ALIVE_RESPONSE) {
            nc_keep_alive_decode_res(ctx, buf, bufferSize);
        } else {
            NABTO_LOG_ERROR(LOG, "keep alive received invalid content type");
        }
    } else {
        NABTO_LOG_ERROR(LOG, "keep alive received a not keep alive packet");
    }
    
    
}

np_error_code nc_keep_alive_async_probe(struct np_platform* pl, struct keep_alive_context* ctx,
                                        uint8_t channelId, keep_alive_callback cb, void* data)
{
    return NABTO_EC_FAILED;
}

void nc_keep_alive_send_res_cb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(LOG, "ka response sent with error code: %u", ec);
}

/*
void nc_keep_alive_send(const np_error_code ec, void* data)
{
    uint8_t* ptr = ctx.pl->buf.start(ctx.buf);
    uint8_t* start = ctx.pl->buf.start(ctx.buf);
    if(ec != NABTO_EC_OK) {
        ctx.cb(ec, ctx.data);
        return;
    }

    ctx.bufSize = 0;
    
    *ptr = KEEP_ALIVE;
    ptr++;
    *ptr = KEEP_ALIVE_RESPONSE;
    ptr++;
    ptr = uint16_write_forward(ptr, 0);
    ptr = uint16_write_forward(ptr, 0);
    ctx.bufSize = ptr - start;
    NABTO_LOG_BUF(NABTO_LOG_MODULE_ATTACHER, ctx.pl->buf.start(ctx.buf), ctx.bufSize);
    ctx.pl->dtlsC.async_send_to(ctx.pl, ctx.conn, ctx.pl->buf.start(ctx.buf), ctx.bufSize, &nc_keep_alive_sent_cb, &ctx);
}

*/
