#include "nm_mbedtls_timer.h"

#include <platform/np_platform.h>
#include <platform/np_timestamp_wrapper.h>
#include <string.h>

np_error_code nm_mbedtls_timer_init(struct nm_mbedtls_timer* timer, struct np_platform* pl, nm_mbedtls_timer_callback cb, void* userData)
{
    memset(timer, 0, sizeof(struct nm_mbedtls_timer));
    timer->pl = pl;
    timer->cb = cb;
    timer->cbData = userData;

    return np_event_queue_create_timed_event(pl, cb, userData, &timer->tEv);
}

void nm_mbedtls_timer_deinit(struct nm_mbedtls_timer* timer)
{
    np_event_queue_destroy_timed_event(timer->pl, timer->tEv);
}

void nm_mbedtls_timer_cancel(struct nm_mbedtls_timer* timer)
{
    np_event_queue_cancel_timed_event(timer->pl, timer->tEv);
}

void nm_mbedtls_timer_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds)
{
    struct nm_mbedtls_timer* ctx = data;
    struct np_platform* pl = ctx->pl;
    struct np_timestamp* ts = &pl->timestamp;
    if (finalMilliseconds == 0) {
        // disable current timer
        np_event_queue_cancel_timed_event(ctx->pl, ctx->tEv);
        ctx->finalTp = 0;
    } else {
        ctx->intermediateTp = np_timestamp_future(ts, intermediateMilliseconds);
        ctx->finalTp = np_timestamp_future(ts, finalMilliseconds);
        np_event_queue_cancel_timed_event(pl, ctx->tEv);
        np_event_queue_post_timed_event(pl, ctx->tEv, finalMilliseconds);
    }
}

int nm_mbedtls_timer_get_delay(void* data)
{
    struct nm_mbedtls_timer* ctx = data;
    struct np_platform* pl = ctx->pl;
    struct np_timestamp* ts = &pl->timestamp;
    if (ctx->finalTp) {
        if (np_timestamp_passed_or_now(ts, ctx->finalTp)) {
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
