#include "nabto_device_future.h"
#include "nabto_device_threads.h"

#include <platform/np_logging.h>

#include <stdlib.h>
#define LOG NABTO_LOG_MODULE_API

typedef uint32_t nabto_device_duration_t_;
void nabto_device_post_future(NabtoDevice* device, NabtoDeviceFuture* fut);

NabtoDeviceFuture* nabto_device_future_new(NabtoDevice* dev)
{
    struct nabto_device_future* fut = malloc(sizeof(struct nabto_device_future));
    memset(fut, 0, sizeof(struct nabto_device_future));
    fut->ready = false;
    fut->dev = dev;
    fut->mutex = nabto_device_threads_create_mutex();
    if (fut->mutex == NULL) {
        NABTO_LOG_ERROR(LOG, "mutex init has failed");
        free(fut);
        return NULL;
    }
    fut->cond = nabto_device_threads_create_condition();
    if (fut->cond == NULL) {
        NABTO_LOG_ERROR(LOG, "condition init has failed");
        nabto_device_threads_free_mutex(fut->mutex);
        free(fut);
        return NULL;
    }
    return (NabtoDeviceFuture*)fut;
}

void NABTO_DEVICE_API nabto_device_future_free(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    free(fut);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_future_ready(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    if (fut->ready) {
        return NABTO_EC_OK;
    } else {
        return NABTO_EC_API_FUTURE_NOT_READY;
    }
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_future_set_callback(NabtoDeviceFuture* future,
                                                  NabtoDeviceFutureCallback callback,
                                                  void* data)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    fut->cb = callback;
    fut->cbData = data;
    if (fut->ready) {
        nabto_device_post_future(fut->dev, (NabtoDeviceFuture*)fut);
    }
    return NABTO_EC_OK;
}


void NABTO_DEVICE_API nabto_device_future_wait(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;

    nabto_device_threads_mutex_lock(fut->mutex);
    nabto_device_threads_cond_wait(fut->cond, fut->mutex);
    nabto_device_threads_mutex_unlock(fut->mutex);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_future_timed_wait(NabtoDeviceFuture* future, nabto_device_duration_t ms)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    if (fut->ready) {
        return NABTO_EC_OK;
    }
    nabto_device_threads_mutex_lock(fut->mutex);
    nabto_device_threads_cond_timed_wait(fut->cond, fut->mutex, ms);
    nabto_device_threads_mutex_unlock(fut->mutex);
    return NABTO_EC_OK;
}


NabtoDeviceError NABTO_DEVICE_API nabto_device_future_error_code(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;

    return fut->ec;
}

NabtoDeviceError nabto_device_future_resolve(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    fut->ready = true;
    NABTO_LOG_TRACE(LOG, "signalling future condition");
    if(fut->cb != NULL) {
        fut->cb(future, fut->ec, fut->cbData);
    } else {
        nabto_device_threads_mutex_lock(fut->mutex);
        nabto_device_threads_cond_signal(fut->cond);
        nabto_device_threads_mutex_unlock(fut->mutex);
    }
    return NABTO_EC_OK;
}

void nabto_api_future_set_error_code(NabtoDeviceFuture* future, const NabtoDeviceError ec)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    fut->ec = ec;
}
