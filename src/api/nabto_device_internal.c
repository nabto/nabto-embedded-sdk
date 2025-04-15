#include "nabto_device_internal.h"
#include <api/nabto_device_defines.h>
#include <api/nabto_device_error.h>
#include <platform/np_error_code.h>
#include <platform/np_error_code.h>
#include <platform/np_logging.h>

void NABTO_DEVICE_API
nabto_device_disable_certificate_validation(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    nc_attacher_disable_certificate_validation(&dev->core.attacher);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

bool NABTO_DEVICE_API
nabto_device_is_attached(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    bool status = dev->core.attacher.state == NC_ATTACHER_STATE_ATTACHED;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return status;
}
