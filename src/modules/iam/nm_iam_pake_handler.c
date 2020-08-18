#include "nm_iam_pake_handler.h"
#include "nm_iam.h"

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
    nabto_device_password_authentication_request_init_listener(device, handler->listener);
    start_listen(handler);
    return NABTO_DEVICE_EC_OK;
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
    struct nm_iam_pake_handler *handler = userData;

    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    } else {
        handle_request(handler, handler->request);
        nabto_device_password_authentication_request_free(handler->request);
        start_listen(handler);
    }
}

void handle_request(struct nm_iam_pake_handler *handler, NabtoDevicePasswordAuthenticationRequest *request)
{
    const char *username = nabto_device_password_authentication_request_get_username(request);

    if (handler->iam->pairingPassword &&
        username && *username == '\0')
    {
        nabto_device_password_authentication_request_set_password(request, handler->iam->pairingPassword);
    }
}

