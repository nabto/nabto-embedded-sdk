
#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "nabto_device_threads.h"
#include "nabto_device_defines.h"
#include <api/nabto_device_error.h>

#include <modules/mbedtls/nm_mbedtls_util.h>

#include <platform/np_allocator.h>

void NABTO_DEVICE_API nabto_device_string_free(char* str)
{
    np_free(str);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_create_private_key(NabtoDevice* device, char** privateKey)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    *privateKey = NULL;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nm_dtls_util_create_private_key(privateKey);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}
