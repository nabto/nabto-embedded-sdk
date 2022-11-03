
#include <nabto/nabto_device_config.h>
#include <nabto/nabto_device_experimental.h>

#include <platform/np_logging.h>
#include <platform/np_allocator.h>

#include <api/nabto_device_error.h>

#if defined(NABTO_DEVICE_MBEDTLS)


#define LOG NABTO_LOG_MODULE_API

#include <modules/mbedtls/nm_mbedtls_util.h>

#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(m) m
#endif

NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_private_key_secp256r1(NabtoDevice* device, const uint8_t* key, size_t keyLength)
{
    char* buffer;
    np_error_code ec;
    if ((ec = nm_mbedtls_util_pem_from_secp256r1(key, keyLength, &buffer)) != NABTO_EC_OK) {
            return nabto_device_error_core_to_api(ec);
    }
    NabtoDeviceError err = nabto_device_set_private_key(device, (const char*)buffer);
    np_free(buffer);
    return err;
}

#endif
