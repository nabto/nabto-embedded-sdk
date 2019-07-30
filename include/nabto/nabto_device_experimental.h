#ifndef _NABTO_DEVICE_EXPERIMENTAL_H_
#define _NABTO_DEVICE_EXPERIMENTAL_H_

#include "nabto_device.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif


/**************
 * Connection *
 **************/

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_client_fingerprint_hex(NabtoDevice* device, NabtoDeviceConnectionRef ref, char** fp);

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

extern const NabtoDeviceError NABTO_DEVICE_EC_IAM_DENY;

extern const NabtoDeviceError NABTO_DEVICE_EC_INVALID_ARGUMENT;

/**
 * IAM decision context for a query, the environment contains all the
 * neccessary attributes and user information to decide if the given
 * action is allowed.
 */
typedef struct NabtoDeviceIamEnv_ NabtoDeviceIamEnv;

/**
 * Callback when the iam system has been modified. The application can choose to persist the changes.
 */
typedef void (*NabtoDeviceIamChangedCallback)(void* userData);

/**
 * Dump all iam state in a single cbor object such that it can be
 * persisted.
 *
 * @param version  the current version of the iam database
 * @param buffer   if NULL or too small the function returns OUT_OF_MEMORY
 *                 and used is set to the required buffer size
 * @return
 *  NABTO_DEVICE_EC_OK             If ok.
 *  NABTO_DEVICE_EC_OUT_OF_MEMORY  If the buffer is too small.
 *  NABTO_DEVICE_EC_FAILED         If an unknown error has happened.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_dump(NabtoDevice* device, uint64_t* version, void* buffer, size_t bufferLength, size_t* used);

// Load iam state from a cbor file.
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_load(NabtoDevice* device, void* cbor, size_t cborLength);

// Listen for changes. Resolves imediately, if the current version is
// greater than version.
NABTO_DEVICE_DECL_PREFIX NabtoDeviceFuture* NABTO_DEVICE_API
nabto_device_iam_listen_for_changes(NabtoDevice* device, uint64_t version);

/**
 * Decide if action is allowed given the decision context.
 *
 * The cbor data is a key value map with attribute:(string|number) pairs. e.g.
 *
 * {
 *   "Pairing:IsPaired": 0,
 *   "Pairing:Password": "..."
 * }
 *
 * @return NABTO_DEVICE_EC_OK iff the action is allowed.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_check_action_attributes(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, const char* action, void* attributesCbor, size_t cborLength);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_check_action(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, const char* action);

/**
 * Set a default user for a connection if no other users with the
 * given fingerprint exists on the system
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_set_default_user(NabtoDevice* device, const char* user);

/**
 * Add a user to the system which is not meant to be persisted in the
 * iam system. This is usually called from an coap resource which
 * validates a JWT access token, the jwt token then defines which
 * roles the user has.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_add_federated_user(NabtoDevice* device, const char* user);

/**
 * Set the user a connection is associated with, this is often used
 * together with jwt and a federated user.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_connection_set_user(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, const char* user);

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
nabto_device_iam_users_add_fingerprint(NabtoDevice* device, const char* user, const char* fingerprint);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_users_remove_fingerprint(NabtoDevice* device, const char* user, const char* fingerprint);


NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_list(NabtoDevice* device, void** cbor, size_t* cborLength);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_get(NabtoDevice* device, const char* role, void** cbor, size_t* cborLength);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_create(NabtoDevice* device, const char* role);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_delete(NabtoDevice* device, const char* role);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_roles_add_policy(NabtoDevice* device, const char* role, const char* policy);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_deivce_iam_roles_remove_policy(NabtoDevice* device, const char* role, const char* policy);


/**
 * Create or update a policy.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_create(NabtoDevice* device, const char* policy, void* cbor, size_t cborLength);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_delete(NabtoDevice* device, const char* policy);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_get(NabtoDevice* device, const char* policy, void** cbor, size_t* cborLength);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_policy_list(NabtoDevice* device, void** cbor, size_t* cborLength);




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
