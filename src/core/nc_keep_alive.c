#include "nc_keep_alive.h"
#include <platform/np_event_queue.h>
#include <platform/np_logging.h>
#include <core/nc_packet.h>
struct keep_alive_context
{
    struct np_platform* pl;
    np_crypto_context* conn;
    keep_alive_callback cb;
    void* data;
    struct np_timed_event ev;
    np_communication_buffer* buf;
    uint16_t bufSize;
    
};

struct keep_alive_context ctx;
void nc_keep_alive_send(const np_error_code ec, void* data);
    
void nc_keep_alive_sent_cb(const np_error_code ec, void* data)
{
    if(ec != NABTO_EC_OK) {
        ctx.cb(ec, ctx.data);
        return;
    }
    np_event_queue_post_timed_event(ctx.pl, &ctx.ev, NABTO_KEEP_ALIVE_DEVICE_INTERVAL, &nc_keep_alive_send, &ctx);
}

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

void nc_keep_alive_start(struct np_platform* pl, np_crypto_context* conn, keep_alive_callback cb, void* data)
{
    ctx.pl = pl;
    ctx.conn = conn;
    ctx.cb = cb;
    ctx.data = data;
    ctx.buf = ctx.pl->buf.allocate();
    np_event_queue_post_timed_event(pl, &ctx.ev, NABTO_KEEP_ALIVE_DEVICE_INTERVAL, &nc_keep_alive_send, &ctx);
}

void nc_keep_alive_recv(const np_error_code ec, np_communication_buffer* buf, uint16_t bufferSize)
{
    NABTO_LOG_INFO(NABTO_LOG_MODULE_ATTACHER, "Received keep alive packet");
    NABTO_LOG_BUF(NABTO_LOG_MODULE_ATTACHER, ctx.pl->buf.start(buf), bufferSize);
}
