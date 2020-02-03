#ifndef _NABTO_DEVICE_EXPERIMENTAL_H_
#define _NABTO_DEVICE_EXPERIMENTAL_H_

#include "nabto_device.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Iam take 2,
 */
typedef struct NabtoDeviceIamRequest_ NabtoDeviceIamRequest;

NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_iam_request_free(NabtoDeviceIamRequest* request);

NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_iam_request_allow(NabtoDeviceIamRequest* request);

NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_iam_request_deny(NabtoDeviceIamRequest* request);


NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_iam_request_get_action(NabtoDeviceIamRequest* request);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceConnectionRef NABTO_DEVICE_API
nabto_device_iam_request_get_connection_ref(NabtoDeviceIamRequest* request);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError  NABTO_DEVICE_API
nabto_device_iam_request_get_attributes(NabtoDeviceIamRequest* request, void** cbor, size_t* cborLength);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError  NABTO_DEVICE_API
nabto_device_iam_init_listener(NabtoDevice* device, NabtoDeviceListener* listener);

NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_new_iam_request(NabtoDeviceListener* listener, NabtoDeviceFuture* future, NabtoDeviceIamRequest** request);

/*******
 * IAM *
 *******/

NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_IAM_DENY;

NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_INVALID_ARGUMENT;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_NOT_FOUND;

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
 * Override iam check function This function is synchroniously called
 * from the code, It's not allowed to call NabtoDevice api functions
 * from this function.
 */

/**
 * IAM check access callback function.
 *
 * @param attributes  cbor encoded attributes, if NULL no attributes is provided.
 * @return NABTO_DEVICE_EC_OK if access is allowed.
 *         NABTO_DEVICE_EC_IAM_DENY if access is not allowed.
 */
typedef NabtoDeviceError (*NabtoDeviceIAMCheckAccessCallback)(NabtoDeviceConnectionRef connectionReference, const char* action, void* attributes, size_t attributesLength, void* userData);

/**
 * Override iam check function This function is synchroniously called
 * from the core, It's not allowed to call other NabtoDevice api
 * functions from this function. Since the caller will have a lock on
 * the system.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_iam_override_check_access_implementation(NabtoDevice* device, NabtoDeviceIAMCheckAccessCallback cb, void* userData);


/******************
 * TCP Tunnelling *
 ******************/

/**
 * Enable TCP tunnelling in the device.
 *
 * Tcp tunnelling is a feature which allows clients to tunnel tcp
 * traffic over a nabto connection to the device. TCP tunnelling is
 * stopped when the device is closed. TCP tunnelling will default
 * incoming tunnel requests to 127.0.0.1 if the IP is not provided in
 * the request. The port number has not default value.
 *
 * @param device   The device
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_RESOURCE_EXISTS if already enabled
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_enable_tcp_tunnelling(NabtoDevice* device);

#ifdef __cplusplus
} // extern c
#endif

#endif
