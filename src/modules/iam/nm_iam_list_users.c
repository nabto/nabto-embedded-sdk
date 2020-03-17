#include "nm_iam_list_users.h"

static void start_listen(struct nm_iam_list_users* handler);
static void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void handle_request(struct nm_iam_list_users* handler);

bool nm_iam_list_users_init(struct nm_iam_list_users* handler, NabtoDevice* device, struct nm_iam* iam)
{
    memset(handler, 0, sizeof(struct nm_iam_list_users));
    handler->device = device;
    handler->iam = iam;
    handler->listener = nabto_device_listener_new(device);
    handler->future = nabto_device_future_new(device);
    const char* paths[] = { "iam", "users", NULL };
    nabto_device_coap_init_listener(device, handler->listener, NABTO_DEVICE_COAP_METHOD_GET);
    start_listen(handler);
}

void nm_iam_list_users_deinit(struct nm_iam_list_users* handler)
{
    nabto_device_future_free(handler->future);
    nabto_device_listener_free(handler->listener);
}

void start_listen(struct nm_iam_list_users* handler)
{
    nabto_device_listener_new_coap_request(handler->listener, handler->future, &handler->request);
    nabto_device_future_set_callback(handler->future, &request_callback, handler);
}
