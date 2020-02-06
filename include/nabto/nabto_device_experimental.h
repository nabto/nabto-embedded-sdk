#ifndef _NABTO_DEVICE_EXPERIMENTAL_H_
#define _NABTO_DEVICE_EXPERIMENTAL_H_

#include "nabto_device.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Authorization.
 *
 * The authorization functionality in the Nabto Device SDK is made
 * such that an application built on top of the Nabto Device SDK can
 * take authorization decision for the core.
 */

typedef enum {
    NABTO_DEVICE_AUTHORIZATION_ATTRIBUTE_TYPE_NUMBER,
    NABTO_DEVICE_AUTHORIZATION_ATTRIBUTE_TYPE_STRING
} NabtoDeviceAutorizationAttributeType;

typedef struct NabtoDeviceAuthorizationRequest_ NabtoDeviceAuthorizationRequest;


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




NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_free(NabtoDeviceAuthorizationRequest* request);

/**
 * Call this function to inform the application that the authorization
 * request has been allowed or denied.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_verdict(NabtoDeviceAuthorizationRequest* request, bool verdict);

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
 * Get attribute name
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_name(NabtoDeviceAuthorizationRequest* request, size_t index);

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
