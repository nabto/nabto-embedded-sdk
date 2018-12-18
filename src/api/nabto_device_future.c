#include "nabto_device_future.h"

#include <platform/np_logging.h>

#include <stdlib.h>
#include <sys/time.h>
#define LOG NABTO_LOG_MODULE_API

typedef uint32_t nabto_device_duration_t_;
void nabto_device_resolve_future(NabtoDevice* device, NabtoDeviceFuture* fut);

NabtoDeviceFuture* nabto_device_future_new(NabtoDevice* dev)
{
    struct nabto_device_future* fut = malloc(sizeof(struct nabto_device_future));
    memset(fut, 0, sizeof(struct nabto_device_future));
    fut->ready = false;
    fut->dev = dev;
    if (pthread_mutex_init(&fut->mutex, NULL) != 0) { 
        NABTO_LOG_ERROR(LOG, "mutex init has failed");
        free(fut);
        return NULL; 
    }
    if (pthread_cond_init(&fut->cond, NULL) != 0) {
        NABTO_LOG_ERROR(LOG, "condition init has failed");
        free(fut);
        return NULL;
    }
    return (NabtoDeviceFuture*)fut;
}

void nabto_device_future_free(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    free(future);
}

NabtoDeviceError nabto_device_future_ready(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    if (fut->ready) {
        return NABTO_EC_OK;
    } else {
        return NABTO_EC_API_FUTURE_NOT_READY;
    }
}

NabtoDeviceError nabto_device_future_set_callback(NabtoDeviceFuture* future,
                                                  NabtoDeviceFutureCallback callback,
                                                  void* data)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    fut->cb = callback;
    fut->cbData = data;
    if (fut->ready) {
        nabto_device_resolve_future(fut->dev, (NabtoDeviceFuture*)fut);
    }
    return NABTO_EC_OK;
}


void nabto_device_future_wait(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    
    pthread_mutex_lock(&fut->mutex);
    pthread_cond_wait(&fut->cond, &fut->mutex);
    pthread_mutex_unlock(&fut->mutex);

}

NabtoDeviceError nabto_device_future_timed_wait(NabtoDeviceFuture* future, nabto_device_duration_t ms)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    struct timespec ts;
    struct timeval tp;

    if (fut->ready) {
        return NABTO_EC_OK;
    }
    int rc = gettimeofday(&tp, NULL);
    long future_us = tp.tv_usec+ms*1000;
    ts.tv_nsec = (future_us % 1000000) * 1000;
    ts.tv_sec = tp.tv_sec + future_us / 1000000;

    pthread_mutex_lock(&fut->mutex);
    pthread_cond_timedwait(&fut->cond, &fut->mutex, &ts);
    pthread_mutex_unlock(&fut->mutex);
    return NABTO_EC_OK;
}


NabtoDeviceError nabto_device_future_error_code(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;

    return fut->ec;
}

NabtoDeviceError nabto_device_future_resolve(NabtoDeviceFuture* future)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    fut->ready = true;
    if(fut->cb != NULL) {
        fut->cb(fut->ec, fut->cbData);
    }
    NABTO_LOG_TRACE(LOG, "signalling future condition");
    pthread_mutex_lock(&fut->mutex);
    pthread_cond_signal(&fut->cond);
    pthread_mutex_unlock(&fut->mutex);
}

void nabto_api_future_set_error_code(NabtoDeviceFuture* future, const np_error_code ec)
{
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    fut->ec = ec;
}
