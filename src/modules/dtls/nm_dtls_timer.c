#include "nm_dtls_timer.h"

#include <platform/np_platform.h>
#include <string.h>

np_error_code nm_dtls_timer_init(struct nm_dtls_timer* timer, struct np_platform* pl, nm_dtls_timer_callback cb, void* userData)
{
    memset(timer, 0, sizeof(struct nm_dtls_timer));
    timer->pl = pl;
    timer->cb = cb;
    timer->cbData = userData;

    return np_event_queue_create_timed_event(pl, cb, userData, &timer->tEv);
}

void nm_dtls_timer_deinit(struct nm_dtls_timer* timer)
{
    np_event_queue_destroy_timed_event(timer->pl, timer->tEv);
}

void nm_dtls_timer_cancel(struct nm_dtls_timer* timer)
{
    np_event_queue_cancel_timed_event(timer->pl, timer->tEv);
}

void nm_dtls_timer_set_delay(void* data, uint32_t intermediateMilliseconds, uint32_t finalMilliseconds)
{
    struct nm_dtls_timer* ctx = data;
    if (finalMilliseconds == 0) {
        // disable current timer
        np_event_queue_cancel_timed_event(ctx->pl, ctx->tEv);
        ctx->finalTp = 0;
    } else {
        ctx->pl->ts.set_future_timestamp(&ctx->intermediateTp, intermediateMilliseconds);
        ctx->pl->ts.set_future_timestamp(&ctx->finalTp, finalMilliseconds);
        np_event_queue_cancel_timed_event(ctx->pl, ctx->tEv);
        np_event_queue_post_timed_event(ctx->pl, ctx->tEv, finalMilliseconds);
    }
}

int nm_dtls_timer_get_delay(void* data)
{
    struct nm_dtls_timer* ctx = data;
    struct np_platform* pl = ctx->pl;
    if (ctx->finalTp) {
        if (pl->ts.passed_or_now(&ctx->finalTp)) {
            return 2;
        } else if (pl->ts.passed_or_now(&ctx->intermediateTp)) {
            return 1;
        } else {
            return 0;
        }
    } else {
        return -1;
    }
}
