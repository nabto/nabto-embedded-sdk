#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "nabto_device_defines.h"
#include "nabto_device_future.h"

#include <core/nc_attacher.h>

#include <nn/string.h>
#include <platform/np_allocator.h>

struct nabto_device_fcm_notification {
    struct nabto_device_context* dev;
    struct nc_attacher_fcm_send_context fcmSend;
    struct nabto_device_future* future;
};

NabtoDeviceFcmNotification* NABTO_DEVICE_API
nabto_device_fcm_notification_new(NabtoDevice* device)
{
    struct nabto_device_fcm_notification* n = np_calloc(1, sizeof(struct nabto_device_fcm_notification));
    if (n != NULL) {
        struct nabto_device_context* dev = (struct nabto_device_context*)device;
        n->dev = dev;
    }
    return (NabtoDeviceFcmNotification*)n;
}

void NABTO_DEVICE_API
nabto_device_fcm_notification_free(NabtoDeviceFcmNotification* notification)
{
    if (notification == NULL) {
        return;
    }
    struct nabto_device_fcm_notification* n = (struct nabto_device_fcm_notification*)notification;
    struct nabto_device_context* dev = n->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_free(n->fcmSend.fcmRequest.payload);
    np_free(n->fcmSend.fcmRequest.projectId);
    np_free(n->fcmSend.fcmResponse.body);
    np_free(n);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_fcm_notification_set_project_id(NabtoDeviceFcmNotification* notification, const char* projectId)
{
    struct nabto_device_fcm_notification* n = (struct nabto_device_fcm_notification*)notification;
    struct nabto_device_context* dev = n->dev;
    NabtoDeviceError ec = 0;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (n->fcmSend.fcmRequest.projectId != NULL) {
        np_free(n->fcmSend.fcmRequest.projectId);
    }

    n->fcmSend.fcmRequest.projectId = nn_strdup(projectId, np_allocator_get());
    if (n->fcmSend.fcmRequest.projectId == NULL) {
        ec = NABTO_DEVICE_EC_OUT_OF_MEMORY;
    } else {
        ec = NABTO_DEVICE_EC_OK;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_fcm_notification_set_payload(NabtoDeviceFcmNotification* notification, const char* payload)
{
    struct nabto_device_fcm_notification* n = (struct nabto_device_fcm_notification*)notification;
    struct nabto_device_context* dev = n->dev;
    NabtoDeviceError ec = 0;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (n->fcmSend.fcmRequest.payload != NULL) {
        np_free(n->fcmSend.fcmRequest.payload);
    }

    n->fcmSend.fcmRequest.payload = nn_strdup(payload, np_allocator_get());
    if (n->fcmSend.fcmRequest.payload == NULL) {
        ec = NABTO_DEVICE_EC_OUT_OF_MEMORY;
    } else {
        ec = NABTO_DEVICE_EC_OK;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

static void fcm_send_callback(np_error_code ec, void* userData)
{
    struct nabto_device_fcm_notification* n = userData;
    nabto_device_future_resolve(n->future, ec);
}

void NABTO_DEVICE_API
nabto_device_fcm_send(NabtoDeviceFcmNotification* notification, NabtoDeviceFuture* future)
{
    struct nabto_device_future* f = (struct nabto_device_future*)future;
    struct nabto_device_fcm_notification* n = (struct nabto_device_fcm_notification*)notification;
    struct nabto_device_context* dev = n->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    nabto_device_future_reset(f);
    if (n->future != NULL) {
        nabto_device_future_resolve(f, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    } else {
        n->future = f;

        np_error_code ec = nc_attacher_fcm_send(&dev->core.attacher, &n->fcmSend, fcm_send_callback, n);
        if (ec != NABTO_EC_OK) {
            nabto_device_future_resolve(f, ec);
        }
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

void NABTO_DEVICE_API
nabto_device_fcm_stop(NabtoDeviceFcmNotification* notification)
{
    struct nabto_device_fcm_notification* n = (struct nabto_device_fcm_notification*)notification;
    struct nabto_device_context* dev = n->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    nc_attacher_fcm_send_stop(&n->fcmSend);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

uint16_t NABTO_DEVICE_API
nabto_device_fcm_notification_get_response_status_code(NabtoDeviceFcmNotification* notification)
{
    struct nabto_device_fcm_notification* n = (struct nabto_device_fcm_notification*)notification;
    return n->fcmSend.fcmResponse.statusCode;
}

const char* NABTO_DEVICE_API
nabto_device_fcm_notification_get_response_body(NabtoDeviceFcmNotification* notification)
{
    struct nabto_device_fcm_notification* n = (struct nabto_device_fcm_notification*)notification;
    return n->fcmSend.fcmResponse.body;
}
