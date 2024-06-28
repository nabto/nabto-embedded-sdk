#ifndef _NABTO_DEVICE_EXPERIMENTAL_H_
#define _NABTO_DEVICE_EXPERIMENTAL_H_

#include "nabto_device.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @Deprecated
 * Disable remote access. When disabled, the device will not attempt to connect to the Nabto
 * Basestation and clients will only be able to connect to the device directly (local connection
 * using mdns discovery or with direct candidates). This function must be called before
 * nabto_device_start();
 *
 * This function is in the experimental header as a more clean approach that supports explicit
 * enabling/disabling at runtime will be added in a future release. Currently, to enable again, you
 * will have to stop and start the device instance.
 *
 * TODO: change name to nabto_device_disable_basestation_attach
 *
 * @param device [in]  The device.
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_INVALID_STATE if device is started
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_disable_remote_access(NabtoDevice* device);

/**
 * Crypto Speed test
 *
 * this test the performance of some of the crucial crypto operations used in
 * the nabto platform. The speedtest prints the result using info log
 * statements. The timing information relies on the underlying timestamp
 * integration which is not neccessary guaranteed to be super precise so use the
 * result wisely.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_crypto_speed_test(NabtoDevice* device);

/**
 * Set a custom allocator.
 *
 * This needs to be called before any allocations has happened. If this is not
 * called the default platform calloc and free are used. This does not change
 * the allocator used in mbedtls or libevent.
 */
typedef void* (*NabtoDeviceAllocatorCalloc)(size_t n, size_t size);
typedef void (*NabtoDeviceAllocatorFree)(void* ptr);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_custom_allocator(NabtoDeviceAllocatorCalloc customCalloc, NabtoDeviceAllocatorFree customFree);

/**
 * Get the certificate expiration as a unix timestamp from the certificate which was used when attaching to the basestation.
 *
 * @param device [in]  The device context
 * @param expiry [out] The unix timestamp for when the certificate expires.
 * @retval NABTO_DEVICE_EC_OK  if the device is attached and an expiry is available.
 * @retval NABTO_DEVICE_EC_NOT_ATTACHED if the device is not attached *
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API nabto_device_get_attach_certificate_expiration(NabtoDevice* device, uint64_t* expiration);

#ifdef __cplusplus
} // extern c #endif
#endif

#endif
