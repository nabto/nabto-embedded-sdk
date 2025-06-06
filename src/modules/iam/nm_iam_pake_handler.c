#include "nm_iam_pake_handler.h"
#include "nm_iam.h"
#include "nm_iam_internal.h"
#include "nm_iam_user.h"

#include <nn/log.h>

static const char* LOGM = "iam";

static void start_listen(struct nm_iam_pake_handler *handler);
static void request_callback(NabtoDeviceFuture *future, NabtoDeviceError ec, void *userData);
static void handle_request(struct nm_iam_pake_handler *handler, NabtoDevicePasswordAuthenticationRequest *request);

NabtoDeviceError nm_iam_pake_handler_init(struct nm_iam_pake_handler *handler,
                                          NabtoDevice *device,
                                          struct nm_iam *iam)
{
    handler->device = device;
    handler->iam = iam;
    handler->listener = nabto_device_listener_new(device);
    handler->future = nabto_device_future_new(device);
    if (handler->listener == NULL || handler->future == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }
    NabtoDeviceError ec = nabto_device_password_authentication_request_init_listener(device, handler->listener);
    if (ec != NABTO_DEVICE_EC_OK) {
        NN_LOG_ERROR(handler->iam->logger, LOGM, "Failed to initialize password authentication listener (%s)", nabto_device_error_get_string(ec));
        return ec;
    }
    start_listen(handler);
    return NABTO_DEVICE_EC_OK;
}

void nm_iam_pake_handler_stop(struct nm_iam_pake_handler* handler)
{
    nabto_device_listener_stop(handler->listener);
}

void nm_iam_pake_handler_deinit(struct nm_iam_pake_handler *handler)
{
    nabto_device_future_free(handler->future);
    nabto_device_listener_free(handler->listener);
}

void start_listen(struct nm_iam_pake_handler *handler)
{
    nabto_device_listener_new_password_authentication_request(handler->listener, handler->future, &handler->request);
    nabto_device_future_set_callback(handler->future, request_callback, handler);
}

void request_callback(NabtoDeviceFuture *future, NabtoDeviceError ec, void *userData)
{
    (void)future;
    struct nm_iam_pake_handler *handler = userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }
    struct nm_iam* iam = handler->iam;
    nm_iam_lock(iam);
    handle_request(handler, handler->request);
    nm_iam_unlock(iam);
    nabto_device_password_authentication_request_free(handler->request);
    start_listen(handler);
}

void handle_request(struct nm_iam_pake_handler *handler, NabtoDevicePasswordAuthenticationRequest *request)
{
    struct nm_iam* iam = handler->iam;
    const char *username = nabto_device_password_authentication_request_get_username(request);

    if (username == NULL) {
        return;
    }

    if (strcmp(username, "") == 0) {
        // password open pairing
        if (iam->state->passwordOpenPairing &&
            iam->state->passwordOpenPassword != NULL)
        {
            nabto_device_password_authentication_request_set_password(request, handler->iam->state->passwordOpenPassword);
        }
    } else {
        // Session based login
        struct nm_iam_user* user = nm_iam_internal_find_user(handler->iam, username);
        if (user && user->password) {
            nabto_device_password_authentication_request_set_password(request, user->password);
        }
    }
}
