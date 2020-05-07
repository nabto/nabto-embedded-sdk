#include <nabto/nabto_device.h>

#include <api/nabto_device_future.h>
#include <api/nabto_device_event_handler.h>
#include <api/nabto_api_future_queue.h>

#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

/**
 * Device event listener
 */

const int NABTO_DEVICE_EVENT_ATTACHED = (int)NC_DEVICE_EVENT_ATTACHED;
const int NABTO_DEVICE_EVENT_DETACHED = (int)NC_DEVICE_EVENT_DETACHED;
const int NABTO_DEVICE_EVENT_CLOSED   = (int)NC_DEVICE_EVENT_CLOSED;

struct nabto_device_listen_device_event{
    NabtoDeviceEvent coreEvent;
    struct nn_llist_node eventListNode;
};

struct nabto_device_listen_device_context {
    struct nc_device_events_listener coreListener;
    struct nabto_device_context* dev;
    struct nabto_device_listener* listener;
    NabtoDeviceEvent* userEvent;
};

np_error_code nabto_device_events_listener_cb(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData)
{
    struct nabto_device_listen_device_context* ctx = (struct nabto_device_listen_device_context*)listenerData;
    np_error_code retEc;
    if (ec == NABTO_EC_OK) {
        struct nabto_device_listen_device_event* ev = (struct nabto_device_listen_device_event*)eventData;
        if (ctx->userEvent != NULL) {
            retEc = NABTO_EC_OK;
            *ctx->userEvent = ev->coreEvent;
            ctx->userEvent = NULL;
        } else {
            NABTO_LOG_ERROR(LOG, "Tried to resolve device event but reference was invalid");
            retEc = NABTO_EC_UNKNOWN;
        }
        free(ev);
    } else if (ec == NABTO_EC_ABORTED) {
        nc_device_remove_device_events_listener(&ctx->dev->core, &ctx->coreListener);
        free(ctx);
        retEc = ec;
    } else {
        free(eventData);
        retEc = ec;
    }
    return retEc;
}

void nabto_device_events_core_cb(enum nc_device_event event, void* userData)
{
    struct nabto_device_listen_device_context* ctx = (struct nabto_device_listen_device_context*)userData;
    struct nabto_device_listen_device_event* ev = (struct nabto_device_listen_device_event*)calloc(1, sizeof(struct nabto_device_listen_device_event));
    if (ev == NULL) {
        nabto_device_listener_set_error_code(ctx->listener, NABTO_EC_OUT_OF_MEMORY);
        return;
    }
    ev->coreEvent = (int)event;
    np_error_code ec = nabto_device_listener_add_event(ctx->listener, &ev->eventListNode, ev);
    if (ec != NABTO_EC_OK) {
        free(ev);
    }
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_device_events_init_listener(NabtoDevice* device, NabtoDeviceListener* deviceListener)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_listen_device_context* ctx = (struct nabto_device_listen_device_context*)calloc(1, sizeof(struct nabto_device_listen_device_context));
    if (ctx == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec = nabto_device_listener_init(dev, listener, NABTO_DEVICE_LISTENER_TYPE_DEVICE_EVENTS, &nabto_device_events_listener_cb, ctx);
    if (ec) {
        free(ctx);
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_error_core_to_api(ec);
    }
    ctx->dev = dev;
    ctx->listener = listener;
    nc_device_add_device_events_listener(&dev->core, &ctx->coreListener, &nabto_device_events_core_cb, ctx);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

void NABTO_DEVICE_API nabto_device_listener_device_event(NabtoDeviceListener* deviceListener, NabtoDeviceFuture* future, NabtoDeviceEvent* event)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_context* dev = listener->dev;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (nabto_device_listener_get_type(listener) != NABTO_DEVICE_LISTENER_TYPE_DEVICE_EVENTS) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_future_resolve(fut, NABTO_DEVICE_EC_INVALID_ARGUMENT);
    }
    np_error_code ec = nabto_device_listener_get_status(listener);
    if (ec != NABTO_EC_OK) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_future_resolve(fut, nabto_device_error_core_to_api(ec));
    }
    struct nabto_device_listen_device_context* ctx = (struct nabto_device_listen_device_context*)nabto_device_listener_get_listener_data(listener);

    ec = nabto_device_listener_init_future(listener, fut);
    if (ec != NABTO_EC_OK) {
        nabto_device_future_resolve(fut, ec);
    } else {
        ctx->userEvent = event;
        nabto_device_listener_try_resolve(listener);
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
}
