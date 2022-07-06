#include <nabto/nabto_device_experimental.h>
#include "nabto_device_defines.h"

#include <core/nc_stream_manager.h>

#include <platform/np_allocator.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_API


NabtoDeviceError NABTO_DEVICE_API
nabto_device_limit_stream_segments(NabtoDevice* device, size_t limit)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    nc_stream_manager_set_max_segments(&dev->core.streamManager, limit);

    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_custom_allocator(NabtoDeviceAllocatorCalloc customCalloc, NabtoDeviceAllocatorFree customFree)
{
    struct nn_allocator a;
    a.calloc = customCalloc;
    a.free = customFree;
    np_allocator_set(&a);
    return NABTO_DEVICE_EC_OK;
}
