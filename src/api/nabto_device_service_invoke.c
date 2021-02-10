#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "nabto_device_defines.h"
#include "nabto_device_future.h"

#include <core/nc_attacher.h>

struct nabto_device_service_invoke {
    struct nabto_device_context* dev;
    struct nc_attacher_service_invoke_context serviceInvoke;
    struct nabto_device_future* future;
};

NabtoDeviceServiceInvoke* NABTO_DEVICE_API
nabto_device_service_invoke_new(NabtoDevice* device)
{
    struct nabto_device_service_invoke* s = calloc(1, sizeof(struct nabto_device_service_invoke));
    if (s != NULL) {
        struct nabto_device_context* dev = (struct nabto_device_context*)device;
        s->dev = dev;
    }
    return (NabtoDeviceServiceInvoke*)s;
}

void NABTO_DEVICE_API
nabto_device_service_invoke_free(NabtoDeviceServiceInvoke* serviceInvoke)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    struct nabto_device_context* dev = s->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    free(s->serviceInvoke.serviceInvokeRequest.serviceId);
    free(s->serviceInvoke.serviceInvokeRequest.message);
    free(s->serviceInvoke.serviceInvokeResponse.message);
    free(s);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_service_invoke_set_service_id(NabtoDeviceServiceInvoke* serviceInvoke, const char* serviceId)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    struct nabto_device_context* dev = s->dev;
    NabtoDeviceError ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (s->serviceInvoke.serviceInvokeRequest.serviceId != NULL) {
        free(s->serviceInvoke.serviceInvokeRequest.serviceId);
    }

    s->serviceInvoke.serviceInvokeRequest.serviceId = strdup(serviceId);
    if (s->serviceInvoke.serviceInvokeRequest.serviceId == NULL) {
        ec = NABTO_DEVICE_EC_OUT_OF_MEMORY;
    } else {
        ec = NABTO_DEVICE_EC_OK;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_service_invoke_set_message(NabtoDeviceServiceInvoke* serviceInvoke, const char* message)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    struct nabto_device_context* dev = s->dev;
    NabtoDeviceError ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (s->serviceInvoke.serviceInvokeRequest.message != NULL) {
        free(s->serviceInvoke.serviceInvokeRequest.message);
    }

    s->serviceInvoke.serviceInvokeRequest.message = strdup(message);
    if (s->serviceInvoke.serviceInvokeRequest.message == NULL) {
        ec = NABTO_DEVICE_EC_OUT_OF_MEMORY;
    } else {
        ec = NABTO_DEVICE_EC_OK;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

static void service_invoke_send_callback(np_error_code ec, void* userData)
{
    struct nabto_device_service_invoke* s = userData;
    nabto_device_future_resolve(s->future, ec);
}

void NABTO_DEVICE_API
nabto_device_service_invoke_execute(NabtoDeviceServiceInvoke* serviceInvoke, NabtoDeviceFuture* future)
{
    struct nabto_device_future* f = (struct nabto_device_future*)future;
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    struct nabto_device_context* dev = s->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    nabto_device_future_reset(f);
    if (s->future != NULL) {
        nabto_device_future_resolve(f, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    } else {
        s->future = f;

        np_error_code ec = nc_attacher_service_invoke_execute(&dev->core.attacher, &s->serviceInvoke, service_invoke_send_callback, s);
        if (ec != NABTO_EC_OK) {
            nabto_device_future_resolve(f, ec);
        }
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

void NABTO_DEVICE_API
nabto_device_service_invoke_stop(NabtoDeviceServiceInvoke* serviceInvoke)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    struct nabto_device_context* dev = s->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    nc_attacher_service_invoke_stop(&s->serviceInvoke);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

uint16_t NABTO_DEVICE_API
nabto_device_service_invoke_get_response_status_code(NabtoDeviceServiceInvoke* serviceInvoke)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    return s->serviceInvoke.serviceInvokeResponse.statusCode;
}

const char* NABTO_DEVICE_API
nabto_device_service_invoke_get_response_message(NabtoDeviceServiceInvoke* serviceInvoke)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    return s->serviceInvoke.serviceInvokeResponse.message;
}
