#include "nm_iam_auth_handler.h"

#include "nm_iam.h"
#include "nm_iam_internal.h"

static void start_listen(struct nm_iam_auth_handler* handler);
static void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void handle_request(struct nm_iam_auth_handler* handler, NabtoDeviceAuthorizationRequest* request);

NabtoDeviceError nm_iam_auth_handler_init(struct nm_iam_auth_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    handler->device = device;
    handler->iam = iam;
    handler->listener = nabto_device_listener_new(device);
    handler->future = nabto_device_future_new(device);
    nabto_device_authorization_request_init_listener(device, handler->listener);
    start_listen(handler);
    return NABTO_DEVICE_EC_OK;
}

void nm_iam_auth_handler_stop(struct nm_iam_auth_handler* handler)
{
    nabto_device_listener_stop(handler->listener);
}

void nm_iam_auth_handler_deinit(struct nm_iam_auth_handler* handler)
{
    nabto_device_future_free(handler->future);
    nabto_device_listener_free(handler->listener);
}

void start_listen(struct nm_iam_auth_handler* handler)
{
    nabto_device_listener_new_authorization_request(handler->listener, handler->future, &handler->request);
    nabto_device_future_set_callback(handler->future, request_callback, handler);
}

void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    (void)future;
    struct nm_iam_auth_handler* handler = userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    } else {
        struct nm_iam* iam = handler->iam;
        nm_iam_lock(iam);
        handle_request(handler, handler->request);
        nm_iam_unlock(iam);
        nabto_device_authorization_request_free(handler->request);
        start_listen(handler);
    }
}

void handle_request(struct nm_iam_auth_handler* handler, NabtoDeviceAuthorizationRequest* request)
{
    const char* action = nabto_device_authorization_request_get_action(request);

    struct nn_string_map attributes;
    nn_string_map_init(&attributes);
    size_t attributesSize = nabto_device_authorization_request_get_attributes_size(request);
    for (size_t i = 0; i < attributesSize; i++) {
        const char* key = nabto_device_authorization_request_get_attribute_name(request, i);
        const char* value = nabto_device_authorization_request_get_attribute_value(request, i);
        nn_string_map_insert(&attributes, key, value);
    }
    NabtoDeviceConnectionRef ref = nabto_device_authorization_request_get_connection_ref(request);
    bool verdict = nm_iam_internal_check_access(handler->iam, ref, action, &attributes);

    nabto_device_authorization_request_verdict(request, verdict);

    nn_string_map_deinit(&attributes);
}
