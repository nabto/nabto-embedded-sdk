#ifndef _NABTO_DEVICE_EXPERIMENTAL_H_
#define _NABTO_DEVICE_EXPERIMENTAL_H_

#include "nabto_device.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Starts the optional internal mdns responder/server. The mdns
 * responder can be used if the system does not provide a mdns
 * implementation.
 *
 * Before starting the mdns responder, the product id, and device id
 * has to be set.
 *
 * The responder is stopped when the device is closed.
 */
NabtoDeviceError nabto_device_mdns_start(NabtoDevice* device);


#ifdef __cplusplus
} // extern c
#endif

#endif
