#ifndef _NABTO_DEVICE_EXPERIMENTAL_H_
#define _NABTO_DEVICE_EXPERIMENTAL_H_

#include "nabto_device.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Set a private key for the device.
 *
 * An ecc key pair consists of a private key and a public key. For the
 * ECC group secp256r1 there is an element G which is a generator for
 * the group. The public key is simple k*G, where k is the private key
 * and a simple number. The argument given to this function is the 32
 * bytes which a private key consists of.
 *
 * These bytes can be found using openssl ec -in key.pem -text and
 * looking into the `priv:` section or using an asn1 parser. Or they
 * can be generated.
 *
 * Not all 32 byte strings are valid private keys. The range of valid
 * private keys for secp256r1 are [1,n-1] where n = FFFFFFFF 00000000
 * FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
 *
 * @param device  the device
 * @param key  The key as 32 bytes data.
 * @param keyLength  Must be 32.
 * @return NABTO_DEVICE_EC_OK  iff the key could be set.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_private_key_secp256r1(NabtoDevice* device, const uint8_t* key, size_t keyLength);


/**
 * Query whether a given connection is local.
 *
 * A connection is considered local if it is currently communicating
 * though a socket only used for local traffic. This ensures the
 * device has not opened any connections through local firewall. Note
 * this assumes the device is behind a firewall. If the device is not
 * behind a firewall, it is possible for a connection to be falsely
 * considered local.
 *
 * The result of this query should not be cached as it may change.
 *
 * @param device [in]  The device.
 * @param ref [in]     The connection reference to query.
 *
 * @return true iff local, false otherwise
 */
NABTO_DEVICE_DECL_PREFIX bool NABTO_DEVICE_API
nabto_device_connection_is_local(NabtoDevice* device,
                                 NabtoDeviceConnectionRef ref);


/**
 * Limit memory usage for streaming
 *
 * This function limits the amount of segments which can be allocated
 * for streaming. A segment is 256 bytes of data, so the max allocated
 * memory for streaming is limit*256bytes.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_limit_stream_segments(NabtoDevice* device, size_t limit);




/**
 * Password Authentication
 *
 * Password authenticate the client and the device. The password
 * authentication is bidirectional and based on PAKE, such that both
 * the client and the device learns that the other end knows the
 * password, without revealing the password to the other end.
 * Password authentication.
 *
 * Usage:
 *  1. Create a new listener. nabto_device_listener_new()
 *  2. Init the listener to listen for password_authentication_requests. nabto_device_password_authentication_request_init_listener()
 *  3. Listen for events on the listener. nabto_device_listener_new_password_authentication_request()
 *  4. Handle the password authentication request
 *  4a. Get the username used for the request. nabto_device_password_authentication_request_get_username()
 *  4b. Set a password to use with the username. nabto_device_password_authentication_request_set_password()
 *  4c. Free the password authentication request. nabto_device_password_authentication_request_free()
 *  5. Later, use the state of the password exchange. nabto_device_connection_is_password_authenticated()
 */

typedef struct NabtoDevicePasswordAuthenticationRequest_ NabtoDevicePasswordAuthenticationRequest;

/**
 * Init a listener for password authentication request listener.
 *
 * @param device    The device.
 * @param listener  The listener.
 * @return NABTO_DEVICE_EC_OK  iff the listener is initialized
 *         NABTO_DEVICE_EC_IN_USE if a password authentucation listener is already set up.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_password_authentication_request_init_listener(NabtoDevice* device, NabtoDeviceListener* listener);

/**
 * Listen for a new password authentication request.
 *
 * This follows the listener/future pattern of getting events
 * asynchronously.
 *
 * @param listener  The listener
 * @param future    The future to wait on.
 * @param request   The resulting request if the future completes with NABTO_DEVICE_EC_OK.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_new_password_authentication_request(NabtoDeviceListener* listener, NabtoDeviceFuture* future, NabtoDevicePasswordAuthenticationRequest** request);

/**
 * Get the username used in the password authentication request. The
 * lifetime of the returned username is until
 * nabto_device_password_authentication_request_free is called.
 *
 * @param request  The request
 * @return The NULL terminated username.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_password_authentication_request_get_username(NabtoDevicePasswordAuthenticationRequest* request);

/**
 * Set password for the request. If password matching the request is
 * found, supply NULL as the password. If NULL is provided, the
 * password authentication protocol continues such that the client
 * doesn't if the username or the password was invalid. The password
 * pointer is not used after the call returns.
 *
 * @param request  The request
 * @param password Null terminated password string
 * @return NABTO_DEVICE_EC_OK
 *         NABTO_DEVICE_EC_INVALID_STATE
 *             if the function is called more than once for
 *             a password authentication request.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_password_authentication_request_set_password(NabtoDevicePasswordAuthenticationRequest* request, const char* passwd);

/**
 * Free a password authentication request.
 *
 * Before this function is called a password should be set for the
 * request. If no password was set the effect is the same as setting
 * the password to NULL in
 * nabto_device_password_authentication_request_set_password.
 *
 * @param request  The request
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API nabto_device_password_authentication_request_free(NabtoDevicePasswordAuthenticationRequest* request);

/**
 * Test if the connection is password authenticated.
 *
 * @return true iff the connection is password authenticated.
 */
NABTO_DEVICE_DECL_PREFIX bool NABTO_DEVICE_API
nabto_device_connection_is_password_authenticated(NabtoDevice* device, NabtoDeviceConnectionRef ref);

#ifdef __cplusplus
} // extern c
#endif

#endif
