#include "nc_keep_alive.h"
#include <core/nc_packet.h>
#include <platform/interfaces/np_event_queue.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_KEEP_ALIVE

np_error_code nc_keep_alive_init(struct nc_keep_alive_context* ctx, struct np_platform* pl, keep_alive_wait_callback cb, void* data)
{
    NABTO_LOG_TRACE(LOG, "initializing keep alive");
    ctx->pl = pl;
    ctx->kaInterval = NC_KEEP_ALIVE_DEFAULT_INTERVAL;
    ctx->kaRetryInterval = NC_KEEP_ALIVE_DEFAULT_RETRY_INTERVAL;
    ctx->kaMaxRetries = NC_KEEP_ALIVE_DEFAULT_MAX_RETRIES;
    ctx->lastRecvCount = 0;
    ctx->lastSentCount = 0;
    ctx->lostKeepAlives = 0;

    ctx->n = ctx->kaInterval/ctx->kaRetryInterval;

    return np_event_queue_create_event(&ctx->pl->eq, cb, data, &ctx->keepAliveEvent);
}

void nc_keep_alive_deinit(struct nc_keep_alive_context* ctx)
{
    if (ctx->pl != NULL) { // if init called
        np_event_queue_destroy_event(&ctx->pl->eq, ctx->keepAliveEvent);
    }
}

void nc_keep_alive_stop(struct nc_keep_alive_context* ctx)
{
    if (ctx->keepAliveEvent) {
        np_event_queue_cancel_event(&ctx->pl->eq, ctx->keepAliveEvent);
    }
}

void nc_keep_alive_reset(struct nc_keep_alive_context* ctx)
{
    if (ctx->keepAliveEvent) {
        np_event_queue_cancel_event(&ctx->pl->eq, ctx->keepAliveEvent);
    }
    ctx->kaInterval = NC_KEEP_ALIVE_DEFAULT_INTERVAL;
    ctx->kaRetryInterval = NC_KEEP_ALIVE_DEFAULT_RETRY_INTERVAL;
    ctx->kaMaxRetries = NC_KEEP_ALIVE_DEFAULT_MAX_RETRIES;
    ctx->lastRecvCount = 0;
    ctx->lastSentCount = 0;
    ctx->lostKeepAlives = 0;
}

void nc_keep_alive_set_settings(struct nc_keep_alive_context* ctx, uint32_t interval, uint32_t retryInterval, uint32_t maxRetries)
{
    ctx->kaInterval = interval;
    ctx->kaRetryInterval = retryInterval;
    ctx->kaMaxRetries = maxRetries;
    ctx->n = ctx->kaInterval/ctx->kaRetryInterval;
}

enum nc_keep_alive_action nc_keep_alive_should_send(struct nc_keep_alive_context* ctx, uint32_t recvCount, uint32_t sentCount)
{
    //NABTO_LOG_TRACE(LOG, "lastRecvCount: %u, recvCount: %u, LastSentCount: %u, sentCount: %u, lostKeepAlives %u, n %u", ctx->lastRecvCount, recvCount, ctx->lastSentCount, sentCount, ctx->lostKeepAlives, ctx->n);

    if (recvCount > ctx->lastRecvCount && sentCount > ctx->lastSentCount) {
        ctx->lostKeepAlives = 0;
        ctx->lastRecvCount = recvCount;
        ctx->lastSentCount = sentCount;
        return DO_NOTHING;
    }
    if (ctx->lostKeepAlives > ctx->kaMaxRetries+ctx->n) {
        return KA_TIMEOUT;
    }
    ctx->lostKeepAlives++;
    if(!ctx->isSending && ctx->lostKeepAlives > ctx->n) {
        return SEND_KA;
    }
    return DO_NOTHING;
}

void nc_keep_alive_wait(struct nc_keep_alive_context* ctx)
{
    np_event_queue_post_timed_event(&ctx->pl->eq, ctx->keepAliveEvent, ctx->kaRetryInterval);
}

void nc_keep_alive_create_request(struct nc_keep_alive_context* ctx, uint8_t** buffer, size_t* length)
{
    uint8_t* ptr = ctx->sendBuffer;
    *ptr = AT_KEEP_ALIVE; ptr++;
    *ptr = CT_KEEP_ALIVE_REQUEST; ptr++;
    memset(ptr, 0, 16); // ptr += 16;

    ctx->isSending = true;
    *buffer = ctx->sendBuffer;
    *length = 18;
}

bool nc_keep_alive_handle_request(struct nc_keep_alive_context* ctx, uint8_t* reqBuffer, size_t reqLength, uint8_t** respBuffer, size_t* respLength)
{
    if (reqLength < 18 || ctx->isSending) {
        // dont respond
        return false;
    }
    // respond
    uint8_t*  ptr = ctx->sendBuffer;
    *ptr = AT_KEEP_ALIVE; ptr++;
    *ptr = CT_KEEP_ALIVE_RESPONSE; ptr++;
    memcpy(ptr, reqBuffer+2, 16);
    ctx->isSending = true;
    *respBuffer = ctx->sendBuffer;
    *respLength = 18;
    return true;
}

void nc_keep_alive_packet_sent(const np_error_code ec, void* data)
{
    (void)ec;
    struct nc_keep_alive_context* ctx = data;
    ctx->isSending = false;
}
