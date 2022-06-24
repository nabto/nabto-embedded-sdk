
#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "nabto_device_threads.h"
#include "nabto_device_defines.h"
#include <api/nabto_device_error.h>

#include <platform/np_allocator.h>

#ifdef NABTO_USE_MBEDTLS
#include <modules/mbedtls/nm_mbedtls_util.h>
#endif
#ifdef NABTO_USE_WOLFSSL
#include <modules/wolfssl/nm_wolfssl_util.h>
#endif


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
    ec = NABTO_EC_NOT_IMPLEMENTED;
#if defined(NABTO_USE_MBEDTLS)
    ec = nm_mbedtls_util_create_private_key(privateKey);
#endif
#if defined(NABTO_USE_WOLFSSL)
    ec = nm_wolfssl_util_create_private_key(privateKey);
#endif
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}
