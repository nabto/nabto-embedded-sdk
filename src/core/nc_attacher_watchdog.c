#include "nc_attacher_watchdog.h"

#define LOG NABTO_LOG_MODULE_ATTACHER

static const uint32_t WATCHDOG_TIMEOUT = 600000; // 10min

static void handleStateChanged(struct nc_watchdog_ctx* ctx, enum nc_attacher_attach_state state);
static void timeout(void* data);

np_error_code nc_attacher_watchdog_init(struct nc_watchdog_ctx* ctx, struct np_platform* pl, struct nc_attach_context* attacher, nc_attacher_watchdog_callback callback, void* callbackData)
{
    ctx->pl = pl;
    ctx->attacher = attacher;
    ctx->timeout = WATCHDOG_TIMEOUT;
    ctx->callback = callback;
    ctx->callbackData = callbackData;

    np_error_code ec = np_event_queue_create_event(&pl->eq, &timeout, ctx, &ctx->timer);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    nc_attacher_set_state_listener(attacher, &nc_attacher_watchdog_state_changed, ctx);
    handleStateChanged(ctx, attacher->state);
    return NABTO_EC_OK;
}

void nc_attacher_watchdog_deinit(struct nc_watchdog_ctx* ctx)
{
    np_event_queue_cancel_event(&ctx->pl->eq, ctx->timer);
    np_event_queue_destroy_event(&ctx->pl->eq, ctx->timer);

}

void nc_attacher_watchdog_state_changed(enum nc_attacher_attach_state state, void* data)
{
    struct nc_watchdog_ctx* ctx = (struct nc_watchdog_ctx*)data;
    handleStateChanged(ctx, state);
}

void handleStateChanged(struct nc_watchdog_ctx* ctx, enum nc_attacher_attach_state state)
{
    np_event_queue_cancel_event(&ctx->pl->eq, ctx->timer);
    if (state != NC_ATTACHER_STATE_ATTACHED) {
        np_event_queue_post_timed_event(&ctx->pl->eq, ctx->timer, ctx->timeout);
    }
}

void timeout(void* data)
{
    struct nc_watchdog_ctx* ctx = (struct nc_watchdog_ctx*)data;
    ctx->callback(NC_DEVICE_EVENT_WATCHDOG_FAILURE, ctx->callbackData);
}

void nc_attacher_watchdog_set_timeout(struct nc_watchdog_ctx* ctx, const uint32_t timeout)
{
    ctx->timeout = timeout;
}
