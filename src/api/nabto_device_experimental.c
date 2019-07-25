#include <nabto/nabto_device_experimental.h>
#include "nabto_device_defines.h"

NabtoDeviceError NABTO_DEVICE_API nabto_device_enable_mdns(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    dev->enableMdns = true;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}
