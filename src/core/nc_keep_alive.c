#include "nc_keep_alive.h"
#include <platform/np_event_queue.h>
#include <platform/np_logging.h>
#include <core/nc_packet.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_KEEP_ALIVE

void nc_keep_alive_init(struct nc_keep_alive_context* ctx, struct np_platform* pl, uint32_t interval, uint32_t retryInterval, uint32_t maxRetries)
{
    NABTO_LOG_TRACE(LOG, "starting keep alive with interval: %u, retryInt: %u, maxRetries: %u", interval, retryInterval, maxRetries);
    ctx->pl = pl;
    ctx->kaInterval = interval;
    ctx->kaRetryInterval = retryInterval;
    ctx->kaMaxRetries = maxRetries;
    ctx->lastRecvCount = 0;
    ctx->lastSentCount = 0;
    ctx->lostKeepAlives = 0;

    ctx->n = ctx->kaInterval/ctx->kaRetryInterval;
    return;
}

void nc_keep_alive_deinit(struct nc_keep_alive_context* ctx)
{
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->keepAliveEvent);
}


enum nc_keep_alive_action nc_keep_alive_should_send(struct nc_keep_alive_context* ctx, uint32_t recvCount, uint32_t sentCount)
{
    //NABTO_LOG_TRACE(LOG, "lastRecvCount: %u, recvCount: %u, LastSentCount: %u, sentCount: %u, lostKeepAlives %u, n %u", ctx->lastRecvCount, recvCount, ctx->lastSentCount, sentCount, ctx->lostKeepAlives, ctx->n);

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

void nc_keep_alive_wait(struct nc_keep_alive_context* ctx, keep_alive_wait_callback cb, void* data)
{
    np_event_queue_post_timed_event(ctx->pl, &ctx->keepAliveEvent, ctx->kaRetryInterval, cb, data);
}


void nc_keep_alive_packet_sent(const np_error_code ec, void* data)
{
    struct nc_keep_alive_context* ctx = data;
    ctx->isSending = false;
}
