#ifndef _NABTO_DEVICE_EXPERIMENTAL_H_
#define _NABTO_DEVICE_EXPERIMENTAL_H_

#include "nabto_device.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NABTO_DEVICE_AUTORIZATION_ATTRIBUTE_TYPE_NUMBER,
    NABTO_DEVICE_AUTORIZATION_ATTRIBUTE_TYPE_STRING
} NabtoDeviceAutorizationAttributeType;

/**
 * Iam take 2,
 */
typedef struct NabtoDeviceAuthorizationRequest_ NabtoDeviceAuthorizationRequest;

NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_free(NabtoDeviceAuthorizationRequest* request);

/**
 * Call this function to inform the application that the authorization
 * request has been allowed.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_allow(NabtoDeviceAuthorizationRequest* request);

/**
 * Call this function to inform the application that the authorization
 * request was denied.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_deny(NabtoDeviceAuthorizationRequest* request);

/**
 * Get the action associated with the request.
 *
 * The string should not be freed and the lifetime is limited by the
 * call to nabto_device_authorization_request_free
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_action(NabtoDeviceAuthorizationRequest* request);

/**
 * Get the connection reference this authorization request originates from.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceConnectionRef NABTO_DEVICE_API
nabto_device_authorization_request_get_connection_ref(NabtoDeviceAuthorizationRequest* request);

/**
 * Get the amount of attributes this authorization request contains.
 */
NABTO_DEVICE_DECL_PREFIX size_t NABTO_DEVICE_API
nabto_device_authorization_request_get_attributes_size(NabtoDeviceAuthorizationRequest* request);

/**
 * Get the type of the attribute with the given index.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceAutorizationAttributeType NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_type(NabtoDeviceAuthorizationRequest* request, size_t index);

/**
 * Get an index of the attribute with a given key
 *
 * @return NABTO_DEVICE_EC_OK if the key exists
 *         NABTO_DEVICE_EC_NOT_FOUND if the key does not exists.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_by_name(NabtoDeviceAuthorizationRequest* request, const char* name, size_t* index);

/**
 * Retrieve a string value for a key, if the key is not a string the behavior is undefined.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_string(NabtoDeviceAuthorizationRequest* request, size_t index);

/**
 * Retrieve a number value for a key, if the key is not a number, the behavior is undefined.
 */
NABTO_DEVICE_DECL_PREFIX int64_t NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_number(NabtoDeviceAuthorizationRequest* request, size_t index);

/**
 * Init an authorization request listener.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError  NABTO_DEVICE_API
nabto_device_authorization_request_init_listener(NabtoDevice* device, NabtoDeviceListener* listener);

/**
 * Wait for a new Authorization request.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_new_authorization_request(NabtoDeviceListener* listener, NabtoDeviceFuture* future, NabtoDeviceAuthorizationRequest** request);

NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_ACCESS_DENIED;

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
