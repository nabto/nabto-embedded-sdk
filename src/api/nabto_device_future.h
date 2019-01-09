#ifndef NABTO_DEVICE_FUTURE_H
#define NABTO_DEVICE_FUTURE_H

#include <nabto/nabto_device.h>

#include <nabto_types.h>

#include <pthread.h>

struct nabto_device_future {
    NabtoDevice* dev;
    NabtoDeviceFutureCallback cb;
    void* cbData;
    NabtoDeviceError ec;
    bool ready;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    struct nabto_device_future* next;
};

NabtoDeviceFuture* nabto_device_future_new(NabtoDevice* dev);

NabtoDeviceError nabto_device_future_resolve(NabtoDeviceFuture* future);

void nabto_api_future_set_error_code(NabtoDeviceFuture* future, const np_error_code ec);


#endif // NABTO_DEVICE_FUTURE_H
