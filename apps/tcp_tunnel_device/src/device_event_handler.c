#include "device_event_handler.h"

#include <stdio.h>

static void start_listen(struct device_event_handler* handler);
static void callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void handle_event(struct device_event_handler* handler, NabtoDeviceEvent event);

void device_event_handler_init(struct device_event_handler* handler, NabtoDevice* device)
{
    handler->device = device;
    handler->listener = nabto_device_listener_new(device);
    handler->future = nabto_device_future_new(device);
    nabto_device_device_events_init_listener(device, handler->listener);
}

void device_event_handler_deinit(struct device_event_handler* handler)
{
    nabto_device_future_free(handler->future);
    nabto_device_listener_free(handler->listener);
}


void device_event_handler_blocking_listener(struct device_event_handler* handler)
{
    while(true) {
        nabto_device_listener_device_event(handler->listener, handler->future, &handler->event);
        NabtoDeviceError ec = nabto_device_future_wait(handler->future);
        if (ec != NABTO_DEVICE_EC_OK) {
            return;
        }
        handle_event(handler, handler->event);
        if (handler->event == NABTO_DEVICE_EVENT_CLOSED) {
            return;
        }
    }
}

void start_listen(struct device_event_handler* handler)
{
    nabto_device_listener_device_event(handler->listener, handler->future, &handler->event);
    nabto_device_future_set_callback(handler->future, &callback, handler);
}

void callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    (void)future;
    struct device_event_handler* handler = userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }
    handle_event(handler, handler->event);
    start_listen(handler);
}

void handle_event(struct device_event_handler* handler, NabtoDeviceEvent event)
{
    (void)handler;
    if (event == NABTO_DEVICE_EVENT_ATTACHED) {
        printf("Attached to the basestation\n");
    } else if (event == NABTO_DEVICE_EVENT_DETACHED) {
        printf("Detached from the basestation\n");
    } else if (event == NABTO_DEVICE_EVENT_UNKNOWN_FINGERPRINT) {
        printf("The device fingerprint is not known by the basestation\n");
    } else if (event == NABTO_DEVICE_EVENT_WRONG_PRODUCT_ID) {
        printf("The provided Product ID did not match the fingerprint\n");
    } else if (event == NABTO_DEVICE_EVENT_WRONG_DEVICE_ID) {
        printf("The provided Device ID did not match the fingerprint\n");
    }
}
