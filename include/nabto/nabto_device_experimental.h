#ifndef _NABTO_DEVICE_EXPERIMENTAL_H_
#define _NABTO_DEVICE_EXPERIMENTAL_H_

#include "nabto_device.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Set the application version the device.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_experimental_get_local_port(NabtoDevice* device, uint16_t* port);

#ifdef __cplusplus
} // extern c
#endif

#endif
