#include <nabto/nabto_device.h>
#include <api/nabto_device_defines.h>
#include <api/nabto_device_error.h>

#include <platform/np_error_code.h>
#include "nabto_device_config.h"

NabtoDeviceError NABTO_DEVICE_API nabto_device_enable_mdns(NabtoDevice* device)
{
#if NABTO_DEVICE_MDNS_ENABLED
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nc_device_enable_mdns(&dev->core);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
#else
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
#endif
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_mdns_add_subtype(NabtoDevice* device, const char* subtype)
{
#if NABTO_DEVICE_MDNS_ENABLED
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nc_device_mdns_add_subtype(&dev->core, subtype);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
#else
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
#endif
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_mdns_add_txt_item(NabtoDevice* device, const char* key, const char* value)
{
#if NABTO_DEVICE_MDNS_ENABLED
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nc_device_mdns_add_txt_item(&dev->core, key, value);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
#else
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
#endif
}
