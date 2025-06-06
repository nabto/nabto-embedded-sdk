
#include <nabto/nabto_device.h>
#include <nabto/nabto_device_config.h>
#include <nabto/nabto_device_experimental.h>

#include "nabto_device_defines.h"
#include "nabto_device_threads.h"
#include <api/nabto_device_error.h>

#include <platform/np_allocator.h>

#if defined(NABTO_DEVICE_MBEDTLS)
#include <modules/mbedtls/nm_mbedtls_util.h>
#elif defined(NABTO_DEVICE_WOLFSSL)
#include <modules/wolfssl/nm_wolfssl_util.h>
#else
#error Missing DTLS implementation
#endif


void NABTO_DEVICE_API nabto_device_string_free(char* str)
{
    np_free(str);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_create_private_key(NabtoDevice* device, char** privateKey)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_EC_FAILED;
    *privateKey = NULL;
    nabto_device_threads_mutex_lock(dev->eventMutex);
#if defined(NABTO_DEVICE_MBEDTLS)
    ec = nm_mbedtls_util_create_private_key(privateKey);
#elif defined(NABTO_DEVICE_WOLFSSL)
    ec = nm_wolfssl_util_create_private_key(privateKey);
#else
    ec = NABTO_EC_NOT_IMPLEMENTED;
#endif
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}
