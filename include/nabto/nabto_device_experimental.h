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

/*******
 * IAM *
 *******/

typedef enum {
    NABTO_DEVICE_IAM_EFFECT_DENY,
    NABTO_DEVICE_IAM_EFFECT_ALLOW
} NabtoDeviceIamEffect;

/**
 * The environment contains a connection reference and a list of
 * attributes which is used by the iam system to check an action
 * request.
 */
typedef struct NabtoDeviceIamEnv_ NabtoDeviceIamEnv;

typedef struct NabtoDeviceIamAttributes_ NabtoDeviceIamAttributes;

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_env_add_string_attribute(NabtoDeviceIamEnv* env, const char* attribute, const char* value);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_env_add_number_attribute(NabtoDeviceIamEnv* env, const char* attribute, uint32_t value);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceIamEnv* NABTO_DEVICE_API
nabto_device_iam_env_from_coap_request(NabtoDeviceCoapRequest* request);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceIamEffect NABTO_DEVICE_API
nabto_device_iam_check_action(NabtoDeviceIamEnv* attributes, const char* action);

NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_iam_env_free(NabtoDeviceIamEnv* env);

#ifdef __cplusplus
} // extern c
#endif

#endif
