#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <platform/np_allocator.h>
#include <platform/np_completion_event.h>
#include <platform/np_tcp_wrapper.h>

#include "nabto_device_defines.h"
#include "nabto_device_error.h"
#include "nabto_device_future.h"


struct nabto_device_tcp_probe_context {
    struct nabto_device_context* device;
    struct np_tcp_socket* socket;
    struct np_completion_event completionEvent;
    struct nabto_device_future* future;
    // The application holds a reference until it frees the probe, an
    // outstanding connect holds one through completionEvent.
    struct np_ref ref;
};

static void probe_free(struct nabto_device_tcp_probe_context* probe);
static void probe_release(struct np_ref* ref);
static void connect_callback(const np_error_code ec, void* userData);

NabtoDeviceTcpProbe* NABTO_DEVICE_API nabto_device_tcp_probe_new(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_tcp_probe_context* ctx = np_calloc(1, sizeof(struct nabto_device_tcp_probe_context));
    if (ctx == NULL) {
        return NULL;
    }

    nabto_device_threads_mutex_lock(dev->eventMutex);
    ctx->device = dev;
    np_ref_init(&ctx->ref, &dev->pl.refTracker, &probe_release);

    np_error_code ec = np_tcp_create(&dev->pl.tcp, &ctx->socket);
    if (ec == NABTO_EC_OK) {
        ec = np_completion_event_init(&dev->pl.eq, &ctx->completionEvent, &connect_callback, ctx, &ctx->ref);
    }

    if (ec != NABTO_EC_OK) {
        probe_free(ctx);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    if (ec != NABTO_EC_OK) {
        return NULL;
    }
    return (NabtoDeviceTcpProbe*)ctx;
}

/**
 * Free a TCP probe.
 */
void NABTO_DEVICE_API nabto_device_tcp_probe_free(NabtoDeviceTcpProbe* probe)
{
    struct nabto_device_tcp_probe_context* ctx = (struct nabto_device_tcp_probe_context*)probe;
    struct nabto_device_context* device = ctx->device;
    nabto_device_threads_mutex_lock(device->eventMutex);

    probe_free(ctx);

    nabto_device_threads_mutex_unlock(device->eventMutex);
}

/**
 * Stop a TCP probe. This is a nonblocking stop function.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API nabto_device_tcp_probe_stop(NabtoDeviceTcpProbe* probe)
{
    struct nabto_device_tcp_probe_context* ctx = (struct nabto_device_tcp_probe_context*)probe;
    struct nabto_device_context* device = ctx->device;
    nabto_device_threads_mutex_lock(device->eventMutex);

    np_tcp_abort(&ctx->device->pl.tcp, ctx->socket);

    nabto_device_threads_mutex_unlock(device->eventMutex);
}

/**
 * Check reachability of a tcp service. This function makes a tcp connect
 * to the defined service. If the connect is OK the future resolves with
 * NABTO_DEVICE_EC_OK else an appropriate error is returned.
 */
void nabto_device_tcp_probe_check_reachability(NabtoDeviceTcpProbe* probe, const char* host, uint16_t port, NabtoDeviceFuture* future)
{
    struct nabto_device_tcp_probe_context* ctx = (struct nabto_device_tcp_probe_context*)probe;
    struct nabto_device_context* device = ctx->device;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_threads_mutex_lock(device->eventMutex);

    nabto_device_future_reset(fut);

    if (ctx->future) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    } else {

        struct np_ip_address address;

        if (!np_ip_address_read_v4(host, &address)) {
            nabto_device_future_resolve(fut, NABTO_DEVICE_EC_INVALID_ARGUMENT);
        } else {
            ctx->future = fut;
            np_tcp_async_connect(&device->pl.tcp, ctx->socket, &address, port, &ctx->completionEvent);
        }
    }

    nabto_device_threads_mutex_unlock(device->eventMutex);
}

/**
 * Destroying the socket resolves an outstanding connect. The probe is freed
 * when its callback has resolved the future.
 */
void probe_free(struct nabto_device_tcp_probe_context* ctx)
{
    struct nabto_device_context* device = ctx->device;
    if (ctx->socket != NULL) {
        np_tcp_destroy(&device->pl.tcp, ctx->socket);
        ctx->socket = NULL;
    }
    np_ref_put(&ctx->ref);
}

void probe_release(struct np_ref* ref)
{
    struct nabto_device_tcp_probe_context* ctx = np_ref_container(ref, struct nabto_device_tcp_probe_context, ref);
    np_completion_event_deinit(&ctx->completionEvent);
    np_free(ctx);
}

void connect_callback(const np_error_code ec, void* userData)
{
    struct nabto_device_tcp_probe_context* ctx = userData;
    struct nabto_device_future* future = ctx->future;
    ctx->future = NULL;
    nabto_device_future_resolve(future, nabto_device_error_core_to_api(ec));
}
