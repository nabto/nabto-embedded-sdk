#include "device_event_handler.h"

#include <stdio.h>

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
        } else if (handler->event == NABTO_DEVICE_EVENT_ATTACHED) {
            printf("Attached to the basestation\n");
        } else if (handler->event == NABTO_DEVICE_EVENT_DETACHED) {
            printf("Detached from the basestation\n");
        } else if (handler->event == NABTO_DEVICE_EVENT_CLOSED) {
            return;
        }
    }
}
