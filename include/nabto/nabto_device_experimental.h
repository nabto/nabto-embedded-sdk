#ifndef _NABTO_DEVICE_EXPERIMENTAL_H_
#define _NABTO_DEVICE_EXPERIMENTAL_H_

#include "nabto_device.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Enable the optional mdns server/responder. The server is started when the
 * device is started. Mdns has to be enabled before the device is
 * started. The responder is stopped when the device is closed.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_enable_mdns(NabtoDevice* device);

#ifdef __cplusplus
} // extern c
#endif

#endif
