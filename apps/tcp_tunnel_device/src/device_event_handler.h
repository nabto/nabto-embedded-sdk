#ifndef DEVICE_EVENT_HANDLER_H_
#define DEVICE_EVENT_HANDLER_H_

#include <nabto/nabto_device.h>

struct device_event_handler {
    NabtoDevice* device;
    NabtoDeviceFuture* future;
    NabtoDeviceListener* listener;
    NabtoDeviceEvent event;
};


bool device_event_handler_init(struct device_event_handler* handler, NabtoDevice* device);

void device_event_handler_deinit(struct device_event_handler* handler);

void device_event_handler_blocking_listener(struct device_event_handler* handler);

#endif
