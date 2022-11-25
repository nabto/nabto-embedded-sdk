#include "nabto_device_future.h"
#include "nabto_device_threads.h"
#include "nabto_device_defines.h"

#include <platform/np_logging.h>
#include <platform/np_allocator.h>

#define LOG NABTO_LOG_MODULE_API

typedef uint32_t nabto_device_duration_t_;

#if defined(NABTO_DEVICE_NO_FUTURE_QUEUE)
static void handle_resolved_future_event(void* userData);
#endif

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_future_new(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_future* fut = np_calloc(1, sizeof(struct nabto_device_future));
    if (fut == NULL) {
        return NULL;
    }
    fut->ready = false;
    fut->dev = dev;
    fut->mutex = nabto_device_threads_create_mutex();
    if (fut->mutex == NULL) {
        NABTO_LOG_ERROR(LOG, "mutex init has failed");
        np_free(fut);
        return NULL;
    }
    fut->cond = nabto_device_threads_create_condition();
    if (fut->cond == NULL) {
        NABTO_LOG_ERROR(LOG, "condition init has failed");
        nabto_device_threads_free_mutex(fut->mutex);
        np_free(fut);
        return NULL;
    }

#if defined(NABTO_DEVICE_NO_FUTURE_QUEUE)
    np_error_code ec = np_event_queue_create_event(&dev->pl.eq, handle_resolved_future_event, fut, &fut->futureResolveEvent);
    if (ec != NABTO_EC_OK) {
        nabto_device_future_free((NabtoDeviceFuture*)fut);
        return NULL;
    }
#endif

    return (NabtoDeviceFuture*)fut;
}


void NABTO_DEVICE_API nabto_device_future_free(NabtoDeviceFuture* future)
{
    if (future == NULL) {
        return;
    }
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
#if defined(NABTO_DEVICE_NO_FUTURE_QUEUE)
    struct nabto_device_context* dev = fut->dev;
    np_event_queue_destroy_event(&dev->pl.eq, fut->futureResolveEvent);
#endif
    nabto_device_threads_free_cond(fut->cond);
    nabto_device_threads_free_mutex(fut->mutex);
    np_free(fut);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_future_ready(NabtoDeviceFuture* future)
{
    return nabto_device_future_error_code(future);
}

void NABTO_DEVICE_API nabto_device_future_set_callback(NabtoDeviceFuture* future,
                                                       NabtoDeviceFutureCallback callback,
                                                       void* data)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_threads_mutex_lock(fut->mutex);
    fut->cb = callback;
    fut->cbData = data;
    if (fut->ready) {
#if defined(NABTO_DEVICE_NO_FUTURE_QUEUE)
        struct nabto_device_context* dev = fut->dev;
        np_event_queue_post_no_core_lock(&dev->pl.eq, fut->futureResolveEvent);
#else
        nabto_device_future_queue_post(&fut->dev->futureQueue, fut);
#endif
    }
    nabto_device_threads_mutex_unlock(fut->mutex);

    return;
}


NabtoDeviceError NABTO_DEVICE_API nabto_device_future_wait(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    NabtoDeviceError ec;

    nabto_device_threads_mutex_lock(fut->mutex);
    if (!fut->ready) {
        nabto_device_threads_cond_wait(fut->cond, fut->mutex);
    }
    ec = fut->ec;
    nabto_device_threads_mutex_unlock(fut->mutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_future_timed_wait(NabtoDeviceFuture* future, nabto_device_duration_t ms)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;

    NabtoDeviceError ec;
    nabto_device_threads_mutex_lock(fut->mutex);
    if (fut->ready) {
        ec = fut->ec;
    } else {
        nabto_device_threads_cond_timed_wait(fut->cond, fut->mutex, ms);
        if (fut->ready) {
            ec = fut->ec;
        } else {
            ec = NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED;
        }
    }
    nabto_device_threads_mutex_unlock(fut->mutex);

    return ec;
}


NabtoDeviceError NABTO_DEVICE_API nabto_device_future_error_code(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;

    NabtoDeviceError ec;
    nabto_device_threads_mutex_lock(fut->mutex);
    if (!fut->ready) {
        ec = NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED;
    } else {
        ec = fut->ec;
    }
    nabto_device_threads_mutex_unlock(fut->mutex);

    return ec;
}

void nabto_device_future_reset(struct nabto_device_future* fut)
{
    nabto_device_threads_mutex_lock(fut->mutex);
    fut->ec = 0;
    fut->ready = false;
    fut->cb = NULL;
    fut->cbData = NULL;
    nabto_device_threads_mutex_unlock(fut->mutex);
}


void nabto_device_future_popped(struct nabto_device_future* fut)
{
    nabto_device_threads_mutex_lock(fut->mutex);
    NabtoDeviceFutureCallback cb = fut->cb;
    fut->cb = NULL;
    nabto_device_threads_mutex_unlock(fut->mutex);
    if(cb != NULL) {
        cb((NabtoDeviceFuture*)fut, fut->ec, fut->cbData);
    }
}

void nabto_device_future_resolve(struct nabto_device_future* fut, NabtoDeviceError ec)
{
    nabto_device_threads_mutex_lock(fut->mutex);
    fut->ec = ec;
    fut->ready = true;
    if (fut->cb != NULL) {
#if defined(NABTO_DEVICE_NO_FUTURE_QUEUE)
        struct nabto_device_context* dev = fut->dev;
        np_event_queue_post_no_core_lock(&dev->pl.eq, fut->futureResolveEvent);
#else
        nabto_device_future_queue_post(&fut->dev->futureQueue, fut);
#endif
    } else {
        nabto_device_threads_cond_signal(fut->cond);
    }
    nabto_device_threads_mutex_unlock(fut->mutex);
}

#if defined(NABTO_DEVICE_NO_FUTURE_QUEUE)
void handle_resolved_future_event(void* userData)
{
    struct nabto_device_future* fut = userData;
    nabto_device_future_popped(fut);
}
#endif
