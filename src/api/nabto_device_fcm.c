#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "nabto_device_defines.h"
#include "nabto_device_future.h"

#include <core/nc_attacher.h>

struct nabto_device_fcm_notification {
    struct nabto_device_context* dev;
    struct nc_attacher_fcm_send_context fcmSend;
    struct nabto_device_future* future;
};

NabtoDeviceFcmNotification* NABTO_DEVICE_API
nabto_device_fcm_notification_new(NabtoDevice* device)
{
    struct nabto_device_fcm_notification* n = calloc(1, sizeof(struct nabto_device_fcm_notification));
    if (n != NULL) {
        struct nabto_device_context* dev = (struct nabto_device_context*)device;
        n->dev = dev;
    }
    return (NabtoDeviceFcmNotification*)n;
}

void NABTO_DEVICE_API
nabto_device_fcm_notification_free(NabtoDeviceFcmNotification* notification)
{
    struct nabto_device_fcm_notification* n = (struct nabto_device_fcm_notification*)notification;
    free(n);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_fcm_notification_set_project_id(NabtoDeviceFcmNotification* notification, const char* projectId)
{
    struct nabto_device_fcm_notification* n = (struct nabto_device_fcm_notification*)notification;
    n->fcmSend.fcmRequest.projectId = strdup(projectId);
    if (n->fcmSend.fcmRequest.projectId == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    } else {
        return NABTO_DEVICE_EC_OK;
    }
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_fcm_notification_set_payload(NabtoDeviceFcmNotification* notification, const char* payload)
{
    struct nabto_device_fcm_notification* n = (struct nabto_device_fcm_notification*)notification;
    n->fcmSend.fcmRequest.payload = strdup(payload);
    if (n->fcmSend.fcmRequest.payload == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    } else {
        return NABTO_DEVICE_EC_OK;
    }
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
    if (n->future != NULL) {
        nabto_device_future_resolve(f, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
        return;
    }

    struct nabto_device_context* dev = n->dev;
    n->future = f;

    nc_attacher_fcm_send(&dev->core.attacher, &n->fcmSend, fcm_send_callback, n);

    nabto_device_future_resolve(f, NABTO_DEVICE_EC_NOT_IMPLEMENTED);
    if (n->future != NULL) {
        nabto_device_future_resolve(f, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    }
}

void NABTO_DEVICE_API
nabto_device_fcm_stop(NabtoDeviceFcmNotification* notification)
{
    struct nabto_device_fcm_notification* n = (struct nabto_device_fcm_notification*)notification;
    nc_attacher_fcm_send_stop(&n->fcmSend);
}
