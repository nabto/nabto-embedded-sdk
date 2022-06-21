#include "nm_wolfssl_timer.h"

#include <platform/np_platform.h>
#include <platform/np_timestamp_wrapper.h>
#include <platform/np_event_queue_wrapper.h>
#include <string.h>

static void timer_cb(void* data);

np_error_code nm_wolfssl_timer_init(struct nm_wolfssl_timer* timer, struct np_platform* pl, nm_wolfssl_timer_callback cb, void* userData)
{
    memset(timer, 0, sizeof(struct nm_wolfssl_timer));
    timer->pl = pl;
    timer->cb = cb;
    timer->cbData = userData;
    timer->armed = false;
    timer->expired = true;

    return np_event_queue_create_event(&pl->eq, timer_cb, timer, &timer->tEv);
}

void nm_wolfssl_timer_deinit(struct nm_wolfssl_timer* timer)
{
    np_event_queue_destroy_event(&timer->pl->eq, timer->tEv);
}

void nm_wolfssl_timer_cancel(struct nm_wolfssl_timer* timer)
{
    np_event_queue_cancel_event(&timer->pl->eq, timer->tEv);
}

void nm_wolfssl_timer_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds)
{
    struct nm_wolfssl_timer* ctx = data;
    struct np_platform* pl = ctx->pl;
    struct np_timestamp* ts = &pl->timestamp;
    ctx->expired = false;
    if (finalMilliseconds == 0) {
        // disable current timer
        np_event_queue_cancel_event(&ctx->pl->eq, ctx->tEv);
        ctx->armed = false;
    } else {
        ctx->armed = true;
        ctx->expired = false;
        ctx->intermediateTp = np_timestamp_future(ts, intermediateMilliseconds);
        np_event_queue_cancel_event(&pl->eq, ctx->tEv);
        np_event_queue_post_timed_event(&pl->eq, ctx->tEv, finalMilliseconds);
    }
}

int nm_wolfssl_timer_get_delay(void* data)
{
    struct nm_wolfssl_timer* ctx = data;
    struct np_platform* pl = ctx->pl;
    struct np_timestamp* ts = &pl->timestamp;
    if (ctx->armed) {
        if (ctx->expired) {
            return 2;
        } else if (np_timestamp_passed_or_now(ts, ctx->intermediateTp)) {
            return 1;
        } else {
            return 0;
        }
    } else {
        return -1;
    }
}

void timer_cb(void* data)
{
    struct nm_wolfssl_timer* ctx = (struct nm_wolfssl_timer*)data;
    ctx->expired = true;
    ctx->cb(ctx->cbData);
}
