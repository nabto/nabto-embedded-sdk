#ifndef NC_ATTACHER_WATCHDOG_H
#define NC_ATTACHER_WATCHDOG_H

#include <platform/np_platform.h>
#include <platform/np_completion_event.h>

#include "nc_device.h"
#include "nc_attacher.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*nc_attacher_watchdog_callback)(enum nc_device_event event, void* data);

struct nc_watchdog_ctx {
    struct np_platform* pl;
    struct nc_device_context* device;
    struct nc_attach_context* attacher;
    struct np_event* timer;
    uint32_t timeout;
    nc_attacher_watchdog_callback callback;
    void* callbackData;
};

np_error_code nc_attacher_watchdog_init(struct nc_watchdog_ctx* ctx, struct np_platform* pl, struct nc_attach_context* attacher, nc_attacher_watchdog_callback callback, void* callbackData);
void nc_attacher_watchdog_deinit(struct nc_watchdog_ctx* ctx);


// INTERNAL
void nc_attacher_watchdog_state_changed(enum nc_attacher_attach_state state, void* data);
void nc_attacher_watchdog_set_timeout(struct nc_watchdog_ctx* ctx, const uint32_t timeoutMs);

#ifdef __cplusplus
} // extern c
#endif

#endif //NC_ATTACHER_H
