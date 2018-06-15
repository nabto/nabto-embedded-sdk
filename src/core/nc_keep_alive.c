#include "nc_keep_alive.h"
#include <platform/np_event_queue.h>
#include <platform/np_logging.h>
#include <core/nc_packet.h>

#define LOG NABTO_LOG_MODULE_KEEP_ALIVE

/*void nc_keep_alive_send(const np_error_code ec, void* data);
    
void nc_keep_alive_sent_cb(const np_error_code ec, void* data)
{
    struct keep_alive_context* ctx = (struct keep_alive_context*)data;
    if(ec != NABTO_EC_OK) {
        ctx->cb(ec, ctx->data);
        return;
    }
    np_event_queue_post_timed_event(ctx.pl, &ctx.ev, NABTO_KEEP_ALIVE_DEVICE_INTERVAL, &nc_keep_alive_send, &ctx);
}
*/

void nc_keep_alive_init(struct np_platform* pl, struct keep_alive_context* ctx, np_crypto_context* conn, keep_alive_callback cb, void* data)
{
    ctx->pl = pl;
    ctx->conn = conn;
    ctx->cb = cb;
    ctx->data = data;
    ctx->buf = ctx->pl->buf.allocate();
    ctx->kaInterval = 10;
    ctx->kaRetryInterval = 1;
    ctx->kaMaxRetries = 5;
    ctx->pl->cryp.async_recv_from(ctx->pl, ctx->conn, KEEP_ALIVE, &nc_keep_alive_recv, ctx);
}
void nc_keep_alive_stop(struct np_platform* pl,  struct keep_alive_context* ctx)
{

}

void nc_keep_alive_recv(const np_error_code ec, uint8_t channelId, uint64_t seq,
                        np_communication_buffer* buf, uint16_t bufferSize, void* data)
{
    
    struct keep_alive_context* ctx = (struct keep_alive_context*)data;
    NABTO_LOG_TRACE(LOG, "Received keep alive packet");
    NABTO_LOG_BUF(LOG, ctx->pl->buf.start(buf), bufferSize);
    
}

np_error_code nc_keep_alive_async_probe(struct np_platform* pl, struct keep_alive_context* ctx,
                                        uint8_t channelId, keep_alive_callback cb, void* data)
{
    return NABTO_EC_OK;
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
    ctx.pl->cryp.async_send_to(ctx.pl, ctx.conn, ctx.pl->buf.start(ctx.buf), ctx.bufSize, &nc_keep_alive_sent_cb, &ctx);
}

*/
