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
/**
 * IAM decision context for a query, the environment contains all the
 * neccessary attributes and user information to decide if the given
 * action is allowed.
 */
struct NabtoDeviceIamEnv_ NabtoDeviceIamEnv;

/**
 * Callback when the iam system has been modified. The application can choose to persist the changes.
 */
typedef void (*NabtoDeviceIamChangedCallback)(void* userData);

// flush all iam settings.
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_flush(NabtoDevice* device);

// Called whenever the internal iam representation is changed.
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_set_changed_callback(NabtoDevice* device, NabtoDeviceIamChangedCallback callback, void* userData);

/**
 * Decide if action is allowed given the decision context.
 *
 * @return NABTO_DEVICE_EC_OK iff the action is allowed.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_check_action(NabtoDeviceIamEnv* env, const char* action);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceIamEnv* NABTO_DEVICE_API
nabto_device_iam_env_new(NabtoDevice* device, NabtoDeviceConnectionId connectionId);

NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_iam_env_free(NabtoDeviceIamEnv* env);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_connection_set_user(NabtoDevice* device, NabtoDeviceConnectionId connectionId, const char* user);

// add a user to the iam system
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_create(NabtoDevice* device, const char* user);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_delete(NabtoDevice* device, const char* user);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_get(NabtoDevice* device, const char* user, void** cbor, size_t* cborLength);


NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_list(NabtoDevice* device, void** cbor, size_t* cborLength);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_add_role(NabtoDevice* device, const char* user, const char* role);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_remove_role(NabtoDevice* device, const char* user, const char* role);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_list_roles(NabtoDevice* device* const char* user, void** cbor, size_t cborLength);


NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_create(NabtoDevice* device, const char* role);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_delete(NabtoDevice* device, const char* role);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_add_policy(NabtoDevice* device, const char* role, const char* policy);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_deivce_iam_roles_remove_policy(NabtoDevice* device, const char* role, const char* policy);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_list_policies(NabtoDevice* device, const char* role, void** cbor, size_t cborLength);


NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_create(NabtoDevice* device, void* cbor, size_t cborLength);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_delete(NabtoDevice* device, const char* policy);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_get(NabtoDevice* device, void** cbor, size_t* cborLength);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_list(NabtoDevice* device, void** cbor, size_t* cborLength);





#ifdef __cplusplus
} // extern c
#endif

#endif
