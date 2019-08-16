#ifndef NABTO_DEVICE_FUTURE_H
#define NABTO_DEVICE_FUTURE_H

#include <nabto/nabto_device.h>
#include <api/nabto_device_threads.h>

#include <nabto_types.h>

struct nabto_device_context;

struct nabto_device_future {
    NabtoDevice* dev;
    NabtoDeviceFutureCallback cb;
    void* cbData;
    NabtoDeviceError ec;
    bool ready;
    struct nabto_device_mutex* mutex;
    struct nabto_device_condition* cond;

    struct nabto_device_future* next;
};

struct nabto_device_future* nabto_device_future_new(struct nabto_device_context* dev);

NabtoDeviceError nabto_device_future_resolve(struct nabto_device_future* fut);

void nabto_api_future_set_error_code(struct nabto_device_future* fut, const NabtoDeviceError ec);


#endif // NABTO_DEVICE_FUTURE_H
