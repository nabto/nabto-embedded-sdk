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

/**
 * Free a authorization request.
 */
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
 * Get attribute name
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_name(NabtoDeviceAuthorizationRequest* request, size_t index);

/**
 * Retrieve a string value for a key.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_value(NabtoDeviceAuthorizationRequest* request, size_t index);

/*************************
 * Server Connect Tokens *
 *************************/

/**
 * Add a server connect token to the basestation which the device uses.
 *
 * @param device
 * @param serverConnectToken  The utf8 encoded token which is added to the basestation.
 * @return NABTO_DEVICE_EC_OK if the token is added.
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if the token cannot be stored in the device.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_add_server_connect_token(NabtoDevice* device, const char* serverConnectToken);

/**
 * Get synchronization state of the tokens.
 *
 * The future return ok if sync went ok or we are not attached such that
 * sync is not neccessary.
 *
 * @return NABTO_DEVICE_EC_OK if they are synched
 *         NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if they are being synched
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_is_server_connect_tokens_synchronized(NabtoDevice* device);

/**
 * Generate a sufficient strong random server connect token.
 *
 * The token is NOT added to the system.
 * the resulting token needs to be freed with nabto_device_string_free.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_create_server_connect_token(NabtoDevice* device, char** serverConnectToken);

#ifdef __cplusplus
} // extern c
#endif

#endif
