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
 * limit maximum number of concurrent streams.
 *
 * Clients can create streams. This limits the maximum amount of
 * concurrent streams. Each tunnel connection uses a stream, so this
 * option also has an effect on max allowed tunnel connections.
 *
 * @param device [in]  The device.
 * @param limit [in]  The maximum number of concurrent streams.
 * @return NABTO_DEVICE_EC_OK iff ok
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_limit_streams(NabtoDevice* device, size_t limit);

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
 * Limit maximum number of concurrent client connections.
 *
 * @param device [in]  The device.
 * @param limit [in]  The maximum number of concurrent connections.
 * @return NABTO_DEVICE_EC_OK iff ok
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_limit_connections(NabtoDevice* device, size_t limit);


/**
 * Limit maximum number of concurrent coap server requests.
 *
 * Clients can make make requests to coap server. This defines the
 * maximum allowed number of concurrent requests.
 *
 * @param device [in]  The device.
 * @param limit [in]  The maximum number of concurrent coap server requests.
 * @return NABTO_DEVICE_EC_OK iff ok
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_limit_coap_server_requests(NabtoDevice* device, size_t limit);

/**
 * Disable remote access. When disabled, the device will not attempt to connect to the Nabto
 * Basestation and clients will only be able to connect to the device directly (local connection
 * using mdns discovery or with direct candidates). This function must be called before
 * nabto_device_start();
 *
 * This function is in the experimental header as a more clean approach that supports explicit
 * enabling/disabling at runtime will be added in a future release. Currently, to enable again, you
 * will have to stop and start the device instance.
 *
 * TODO: change name to nabto_device_disable_basestation_attach
 *
 * @param device [in]  The device.
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_INVALID_STATE if device is started
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_disable_remote_access(NabtoDevice* device);

/**
 * Service invocation api
 *
 * This makes it possible to instruct the basestation to invoke an https service
 * on behalf of the device. The basestation has validated the product id and the
 * device id so if the service integration is used together with basic auth the
 * https service can be certain that a specific device id and product id is the
 * originator of a https request.
 */
typedef struct NabtoDeviceServiceInvocation_ NabtoDeviceServiceInvocation;

/**
 * Create a new service invoke object.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceServiceInvocation* NABTO_DEVICE_API
nabto_device_service_invocation_new(NabtoDevice* device);

/**
 * Free a service invoke object
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_service_invocation_free(NabtoDeviceServiceInvocation* serviceInvoke);

/**
 * Stop a service invocation.
 * If a coap request is in progress this request will be stopped.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_service_invocation_stop(NabtoDeviceServiceInvocation* serviceInvoke);

/**
 * Set the service id to invoke. The service id is configured in the nabto cloud console.
 *
 * @param serviceInvoke  The service invoke object
 * @param serviceId  The service id
 * @return NABTO_DEVICE_EC_OK  iff the serviceId is set.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_service_invocation_set_service_id(NabtoDeviceServiceInvocation* serviceInvoke, const char* serviceId);

/**
 * Set the message for the service invocation
 *
 * @param serviceInvoke  The service invoke object
 * @param message  The message
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_service_invocation_set_message(NabtoDeviceServiceInvocation* serviceInvoke, const uint8_t* message, size_t messageLength);

/**
 * Invoke a service. The future resolves with the status of the operation.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_service_invocation_execute(NabtoDeviceServiceInvocation* serviceInvoke, NabtoDeviceFuture* future);

/**
 * Get the status code from the service invocation, the behavior is undefined if
 * the invocation failed.
 */
NABTO_DEVICE_DECL_PREFIX uint16_t NABTO_DEVICE_API
nabto_device_service_invocation_get_response_status_code(NabtoDeviceServiceInvocation* serviceInvoke);

/**
 * Get the response message from the service invocation. The message is undefined
 * if the service invocation failed.
 */
NABTO_DEVICE_DECL_PREFIX const uint8_t* NABTO_DEVICE_API
nabto_device_service_invocation_get_response_message_data(NabtoDeviceServiceInvocation* serviceInvoke);

/**
 * Get the length of the response message from the service invocation. Undefined if the invocation failed.
 */
NABTO_DEVICE_DECL_PREFIX size_t NABTO_DEVICE_API
nabto_device_service_invocation_get_response_message_size(NabtoDeviceServiceInvocation* serviceInvoke);


#ifdef __cplusplus
} // extern c #endif
#endif

#endif