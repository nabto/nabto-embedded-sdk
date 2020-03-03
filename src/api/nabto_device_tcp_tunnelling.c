#include <nabto/nabto_device.h>


NabtoDeviceError NABTO_DEVICE_API nabto_device_enable_tcp_tunnelling(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nm_tcptunnels_init(&dev->tcptunnels, &dev->core);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}
