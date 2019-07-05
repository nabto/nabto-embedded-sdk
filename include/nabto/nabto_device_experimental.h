#ifndef _NABTO_DEVICE_EXPERIMENTAL_H_
#define _NABTO_DEVICE_EXPERIMENTAL_H_

#include "nabto_device.h"
#ifdef __cplusplus
extern "C" {
#endif


/********
 * Util *
 ********/
NABTO_DEVICE_DECL_PREFIX char* NABTO_DEVICE_API
nabto_device_experimental_util_create_private_key(NabtoDevice* device);


NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_experimental_util_free(void* data);

#ifdef __cplusplus
} // extern c
#endif

#endif
