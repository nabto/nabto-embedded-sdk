#ifndef _NABTO_DEVICE_INTERNAL_H_
#define _NABTO_DEVICE_INTERNAL_H_

/**
 * These functions should not be used in production applications they are only meant for testing purposes.
 */

#include <nabto/nabto_device.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Disable basestation certificate validation.
 *
 * This should only be used for testing.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_disable_certificate_validation(NabtoDevice* device);

/**
 * Query the device if it is attached.
 */
NABTO_DEVICE_DECL_PREFIX bool NABTO_DEVICE_API
nabto_device_is_attached(NabtoDevice* device);

#ifdef __cplusplus
} // extern c #endif
#endif

#endif
