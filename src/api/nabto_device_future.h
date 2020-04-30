#ifndef NABTO_DEVICE_FUTURE_H
#define NABTO_DEVICE_FUTURE_H

#include <nabto/nabto_device.h>
#include <api/nabto_device_threads.h>

#include <nabto_types.h>

#include <event.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nabto_device_context;

struct nabto_device_future {
    struct nabto_device_context* dev;
    NabtoDeviceFutureCallback cb;
    void* cbData;
    NabtoDeviceError ec;
    bool ready;
    struct nabto_device_mutex* mutex;
    struct nabto_device_condition* cond;

    struct nabto_device_future* next;
    struct event event;
};

void nabto_device_future_reset(struct nabto_device_future* fut);
void nabto_device_future_popped(struct nabto_device_future* fut);
void nabto_device_future_resolve(struct nabto_device_future* fut, NabtoDeviceError ec);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NABTO_DEVICE_FUTURE_H
