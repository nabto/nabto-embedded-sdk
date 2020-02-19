#include "none_authorization.h"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

NabtoDeviceListener* authorizationListener;
NabtoDeviceFuture* authorizationFuture;
NabtoDeviceAuthorizationRequest* authorizationRequest;

static void authorization_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void start_authorization_listen();


void init_none_authorization(NabtoDevice* device)
{
    authorizationListener = nabto_device_listener_new(device);
    nabto_device_authorization_request_init_listener(device, authorizationListener);
    authorizationFuture = nabto_device_future_new(device);
    start_authorization_listen();
}

void deinit_none_authorization()
{
    nabto_device_listener_stop(authorizationListener);
}

void start_authorization_listen()
{
    nabto_device_listener_new_authorization_request(authorizationListener, authorizationFuture, &authorizationRequest);
    nabto_device_future_set_callback(authorizationFuture, authorization_callback, NULL);
}

void authorization_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    if (ec == NABTO_DEVICE_EC_OK) {
        nabto_device_authorization_request_verdict(authorizationRequest, true);
        nabto_device_authorization_request_free(authorizationRequest);
        start_authorization_listen();
    } else {
        nabto_device_listener_free(authorizationListener);
        nabto_device_future_free(authorizationFuture);
    }
}
