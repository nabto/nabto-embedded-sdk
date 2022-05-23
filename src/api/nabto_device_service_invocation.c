#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "nabto_device_defines.h"
#include "nabto_device_future.h"

#include <core/nc_attacher.h>

#include <platform/np_allocator.h>
#include <nn/string.h>

const int NABTO_DEVICE_SERVICE_INVOKE_MESSAGE_FORMAT_BINARY =
    (int)NC_SERVICE_INVOKE_MESSAGE_FORMAT_BINARY;
const int NABTO_DEVICE_SERVICE_INVOKE_MESSAGE_FORMAT_NONE =
    (int)NC_SERVICE_INVOKE_MESSAGE_FORMAT_NONE;
const int NABTO_DEVICE_SERVICE_INVOKE_MESSAGE_FORMAT_TEXT =
    (int)NC_SERVICE_INVOKE_MESSAGE_FORMAT_TEXT;

struct nabto_device_service_invoke {
    struct nabto_device_context* dev;
    struct nc_attacher_service_invoke_context serviceInvoke;
    struct nabto_device_future* future;
};

NabtoDeviceServiceInvocation* NABTO_DEVICE_API
nabto_device_service_invocation_new(NabtoDevice* device)
{
    struct nabto_device_service_invoke* s = np_calloc(1, sizeof(struct nabto_device_service_invoke));
    if (s != NULL) {
        struct nabto_device_context* dev = (struct nabto_device_context*)device;
        s->dev = dev;
    }
    return (NabtoDeviceServiceInvocation*)s;
}

void NABTO_DEVICE_API
nabto_device_service_invocation_free(NabtoDeviceServiceInvocation* serviceInvoke)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    struct nabto_device_context* dev = s->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_free(s->serviceInvoke.serviceInvokeRequest.serviceId);
    np_free(s->serviceInvoke.serviceInvokeRequest.message);
    np_free(s->serviceInvoke.serviceInvokeResponse.message);
    np_free(s);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_service_invocation_set_service_id(NabtoDeviceServiceInvocation* serviceInvoke, const char* serviceId)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    struct nabto_device_context* dev = s->dev;
    NabtoDeviceError ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (s->serviceInvoke.serviceInvokeRequest.serviceId != NULL) {
        np_free(s->serviceInvoke.serviceInvokeRequest.serviceId);
    }

    s->serviceInvoke.serviceInvokeRequest.serviceId = nn_strdup(serviceId, np_allocator_get());
    if (s->serviceInvoke.serviceInvokeRequest.serviceId == NULL) {
        ec = NABTO_DEVICE_EC_OUT_OF_MEMORY;
    } else {
        ec = NABTO_DEVICE_EC_OK;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_service_invocation_set_message(NabtoDeviceServiceInvocation* serviceInvoke, const uint8_t* message, size_t messageLength)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    struct nabto_device_context* dev = s->dev;
    NabtoDeviceError ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (s->serviceInvoke.serviceInvokeRequest.message != NULL) {
        np_free(s->serviceInvoke.serviceInvokeRequest.message);
    }

    s->serviceInvoke.serviceInvokeRequest.message = np_calloc(1, messageLength);
    if (s->serviceInvoke.serviceInvokeRequest.message == NULL) {
        ec = NABTO_DEVICE_EC_OUT_OF_MEMORY;
    } else {
        ec = NABTO_DEVICE_EC_OK;
        memcpy(s->serviceInvoke.serviceInvokeRequest.message, message, messageLength);
        s->serviceInvoke.serviceInvokeRequest.messageLength = messageLength;
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
nabto_device_service_invocation_execute(NabtoDeviceServiceInvocation* serviceInvoke, NabtoDeviceFuture* future)
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
nabto_device_service_invocation_stop(NabtoDeviceServiceInvocation* serviceInvoke)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    struct nabto_device_context* dev = s->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    nc_attacher_service_invoke_stop(&s->serviceInvoke);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

uint16_t NABTO_DEVICE_API
nabto_device_service_invocation_get_response_status_code(NabtoDeviceServiceInvocation* serviceInvoke)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    return s->serviceInvoke.serviceInvokeResponse.statusCode;
}

const uint8_t* NABTO_DEVICE_API
nabto_device_service_invocation_get_response_message_data(NabtoDeviceServiceInvocation* serviceInvoke)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    return s->serviceInvoke.serviceInvokeResponse.message;
}

size_t NABTO_DEVICE_API
nabto_device_service_invocation_get_response_message_size(NabtoDeviceServiceInvocation* serviceInvoke)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    return s->serviceInvoke.serviceInvokeResponse.messageLength;
}

NabtoDeviceServiceInvokeMessageFormat NABTO_DEVICE_API
nabto_device_service_invocation_get_response_message_format(NabtoDeviceServiceInvocation* serviceInvoke)
{
    struct nabto_device_service_invoke* s = (struct nabto_device_service_invoke*)serviceInvoke;
    return s->serviceInvoke.serviceInvokeResponse.messageFormat;
}
