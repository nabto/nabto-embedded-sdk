#pragma once

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <memory>

struct NabtoDeviceFree {
    void operator ()(NabtoDevice* device) { nabto_device_free(device); }
};
typedef std::unique_ptr<NabtoDevice, NabtoDeviceFree> NabtoDevicePtr;

struct NabtoDeviceListenerFree {
    void operator ()(NabtoDeviceListener* listener) { nabto_device_listener_free(listener); }
};
typedef std::unique_ptr<NabtoDeviceListener, NabtoDeviceListenerFree> NabtoDeviceListenerPtr;


struct NabtoDeviceStringFree {
    void operator ()(char* str) { nabto_device_string_free(str); }
};
typedef std::unique_ptr<char, NabtoDeviceStringFree> NabtoDeviceStringPtr;
