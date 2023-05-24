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
 * @Deprecated
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
 * Add a key-value pair to the metadata of a TCP tunnel service.
 * If the given key already exists in the metadata, then its corresponding value will be overwritten.
 *
 * @param device [in]      The device instance.
 * @param serviceId [in]   The unique id of a service on the device.
 * @param key [in]         The key of the key-value pair.
 * @param value [in]       The value of the key-value pair.
 * @return NABTO_DEVICE_EC_OK if the key-value pair was added to the metadata of the service.
 *         NABTO_DEVICE_EC_NOT_FOUND if no service with the given id was located on the device.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_add_tcp_tunnel_service_metadata(NabtoDevice* device, const char* serviceId, const char* key, const char* value);


/**
 * Remove a key-value pair from the metadata of a TCP tunnel service.
 *
 * @param device [in]      The device instance.
 * @param serviceId [in]   The unique id of a service on the device.
 * @param key [in]         The key of the key-value pair.
 * @return NABTO_DEVICE_EC_OK if the key-value pair was removed or if no key-value pair was found.
 *         NABTO_DEVICE_EC_NOT_FOUND if no service with the given id was located on the device.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_remove_tcp_tunnel_service_metadata(NabtoDevice* device, const char* serviceId, const char* key);

/**
 * Crypto Speed test
 *
 * this test the performance of some of the crucial crypto operations used in
 * the nabto platform. The speedtest prints the result using info log
 * statements. The timing information relies on the underlying timestamp
 * integration which is not neccessary guaranteed to be super precise so use the
 * result wisely.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_crypto_speed_test(NabtoDevice* device);

/**
 * Set a custom allocator.
 *
 * This needs to be called before any allocations has happened. If this is not
 * called the default platform calloc and free are used. This does not change
 * the allocator used in mbedtls or libevent.
 */
typedef void* (*NabtoDeviceAllocatorCalloc)(size_t n, size_t size);
typedef void (*NabtoDeviceAllocatorFree)(void* ptr);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_custom_allocator(NabtoDeviceAllocatorCalloc customCalloc, NabtoDeviceAllocatorFree customFree);

/**
 * Format of the message received by the basestation in a service invocation
 * response
 * ```
 * NABTO_DEVICE_SERVICE_INVOKE_MESSAGE_FORMAT_BINARY;
 * NABTO_DEVICE_SERVICE_INVOKE_MESSAGE_FORMAT_NONE;
 * NABTO_DEVICE_SERVICE_INVOKE_MESSAGE_FORMAT_TEXT;
 * ```
 */
typedef int NabtoDeviceServiceInvokeMessageFormat;

// The HTTP service returned a base64 encoded string of data
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceServiceInvokeMessageFormat
    NABTO_DEVICE_SERVICE_INVOKE_MESSAGE_FORMAT_BINARY;
// The HTTP service returned an empty body, message length is 0.
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceServiceInvokeMessageFormat
    NABTO_DEVICE_SERVICE_INVOKE_MESSAGE_FORMAT_NONE;
// The HTTP service returned a text body.
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceServiceInvokeMessageFormat
    NABTO_DEVICE_SERVICE_INVOKE_MESSAGE_FORMAT_TEXT;


/**
 * Get the message format of a service invocation response. This can be used to determine how to decode the response message. The message format is undefined if the service invocation failed.
 *
 * @param serviceInvocation [in]  The service invocation object.
 * @return The format of the response message.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceServiceInvokeMessageFormat NABTO_DEVICE_API
nabto_device_service_invocation_get_response_message_format(NabtoDeviceServiceInvocation* serviceInvocation);

/**
 * A TCP probe is used to probe for tcp reachability from the device
 * perspective. The intention is that this feature can be used in conjunction
 * with TCP Tunnels to test if the configured services are reachable. Often
 * there are problems on embedded devices with TCP reachability, either the
 * services are not running, people specify the wrong port numbers or the
 * loopback interface is simply not enabled. This leads to confusion about why
 * things are not working, so this is a tool to help debugging these issues.
*/
typedef struct NabtoDeviceTcpProbe_ NabtoDeviceTcpProbe;

/**
 * Create a TCP Probe instance.
 *
 * A TCP Probe instance can be used for a single reachability check. If it is
 * reused for more than one check, the behavior is undefined.
 *
 * @param device [in]  The device.
 * @return A new instance or NULL it the instance could not be allocated.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceTcpProbe* NABTO_DEVICE_API nabto_device_tcp_probe_new(NabtoDevice* device);

/**
 * Free a TCP probe instance.
 * @param probe [in]  The TCP probe to be freed.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API nabto_device_tcp_probe_free(NabtoDeviceTcpProbe* probe);

/**
 * Stop a TCP probe. This is a nonblocking stop function.
 * @param probe [in]  The TCP probe to be freed.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API nabto_device_tcp_probe_stop(NabtoDeviceTcpProbe* probe);

/**
 * Check reachability of a tcp service. This function makes a tcp connect
 * to the defined service. If the connect is OK the future resolves with
 * NABTO_DEVICE_EC_OK else an appropriate error is returned.
 *
 * Future Status:
 *   NABTO_DEVICE_EC_OK  if it was possible to make a TCP connection to the TCP service.
 *   Something else if the reachability check failed.
 *
 * @param probe [in]  The TCP probe to be freed.
 * @param host [in]   The IPV4 host of the TCP service
 * @param port [in]   The port number of the TCP service
 * @param future [in] The future to resolve when the result is ready.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API nabto_device_tcp_probe_check_reachability(NabtoDeviceTcpProbe* probe, const char* host, uint16_t port, NabtoDeviceFuture* future);

/**
 * Get the certificate expiration as a unix timestamp from the certificate which was used when attaching to the basestation.
 *
 * @param device [in]  The device context
 * @param expiry [out] The unix timestamp for when the certificate expires.
 * @retval NABTO_DEVICE_EC_OK  if the device is attached and an expiry is available.
 * @retval NABTO_DEVICE_EC_NOT_ATTACHED if the device is not attached *
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API nabto_device_get_attach_certificate_expiration(NabtoDevice* device, uint64_t* expiration);



/// TURN SERVER CREDENTIALS ////

typedef struct NabtoDeviceIceServersRequest_ NabtoDeviceIceServersRequest;

/**
 * Allocate new ICE servers request.
 *
 * @param device [in] The device context
 * @return The created ICE servers request or NULL on failure
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceIceServersRequest* NABTO_DEVICE_API
nabto_device_ice_servers_request_new(NabtoDevice* device);

/**
 * Free a previously allocated ICE servers request.
 * @param request [in] The request to free.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_ice_servers_request_free(NabtoDeviceIceServersRequest* request);

/**
 * Request ICE Servers from the Basestation.
 *
 * The request takes an `identifier` which, combined with the product ID and device ID, will be used to generate the username for TURN servers. This can be used to differentiate credentials created for the device or for the client.
 *
 * @param identifier [in] Identifier used in the username. Only characters [a-zA-Z0-9-_] are allowed.
 * @param request [in] Request to send
 * @param future [in] Future to resolve when the result is ready.
 * @retval NABTO_DEVICE_EC_OK iff the request was sent.
 * @retval NABTO_DEVICE_EC_INVALID_ARGUMENT if the identifier was invalid.
 * @retval NABTO_DEVICE_EC_NOT_ATTACHED if the device is not attached.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API nabto_device_ice_servers_request_send(const char* identifier, NabtoDeviceIceServersRequest* request, NabtoDeviceFuture* future);

/**
 * Get the number of ICE servers returned from a successfully resolved ICE server request. This count is used to generate indices as [0, count-1] for the get functions below.
 *
 * @param request [in] Request to get count from
 * @return The number of ICE servers returned by the basestation.
 */
NABTO_DEVICE_DECL_PREFIX size_t NABTO_DEVICE_API
nabto_device_ice_servers_request_get_server_count(NabtoDeviceIceServersRequest* request);

/**
 * Get the username of an ICE server from its index.
 *
 * If the ICE server at the index is a STUN server, the username is NULL. The username is freed with the request.
 *
 * @param request [in] The request to get the ICE server from
 * @param index [in] Index of the ICE server to get the username of.
 * @return The username for a TURN server, or NULL for a STUN server.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_ice_servers_request_get_username(NabtoDeviceIceServersRequest* request, size_t index);

/**
 * Get the credential of an ICE server from its index.
 *
 * If the ICE server at the index is a STUN server, the credential is NULL. The credential is freed with the request.
 *
 * @param request [in] The request to get the ICE server from
 * @param index [in] Index of the ICE server to get the credential of.
 * @return The credential for a TURN server, or NULL for a STUN server.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_ice_servers_request_get_credential(NabtoDeviceIceServersRequest* request, size_t index);

/**
 * Get the number of URLs for an ICE server from its index.
 *
 * This count is used to generate URL indices as [0, count-1] for `nabto_device_ice_servers_request_get_url()`.
 *
 * @param request [in] The request to get the ICE server from
 * @param index [in] Index of the ICE server to get the URL count of.
 * @return The number of URLs for the ICE server
 */
NABTO_DEVICE_DECL_PREFIX size_t NABTO_DEVICE_API
nabto_device_ice_servers_request_get_urls_count(NabtoDeviceIceServersRequest* request, size_t index);

/**
 * Get an URL of an ICE server from its index.
 *
 * The URL is freed with the request.
 *
 * @param request [in] The request to get the ICE server from
 * @param serverIndex [in] Index of the ICE server to get the URL from.
 * @param urlIndex [in] Index of the URL to get.
 * @return An URL for the ICE server.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_ice_servers_request_get_url(NabtoDeviceIceServersRequest* request, size_t serverIndex, size_t urlIndex);





/// VIRTUAL CLIENT CONNECTIONS ////
typedef struct NabtoDeviceVirtualConnection_ NabtoDeviceVirtualConnection;

/**
 * Allocate new Virtual Connection.
 *
 * @param device [in] The device context
 * @param vfp [in] A virtual fingerprint to assign to the connection
 * @return The created virtual connection or NULL on failure
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceVirtualConnection* NABTO_DEVICE_API
nabto_device_virtual_connection_new(NabtoDevice* device, const char* vfp);

/**
 * Free a previously allocated virtual connection.
 * @param connection [in] The connection to free.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_virtual_connection_free(NabtoDeviceVirtualConnection* connection);


/**
 * Close a virtual connection.
 * @param connection [in] The connection to close.
 * @param future [in] Future resolved when the connection is closed
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_virtual_connection_close(NabtoDeviceVirtualConnection* connection, NabtoDeviceFuture* future);

/**
 * Test if the connection is virtual.
 *
 * @param device [in]  The device
 * @param ref [in]     The connection reference to query
 * @return true iff the connection is virtual.
 */
NABTO_DEVICE_DECL_PREFIX bool NABTO_DEVICE_API
nabto_device_connection_is_virtual(NabtoDevice* device, NabtoDeviceConnectionRef ref);


typedef struct NabtoDeviceVirtualCoapResponse_ NabtoDeviceVirtualCoapResponse;


/**
 * Invoke a CoAP enpoint on a virtual connection.
 *
 * @param connection [in] The connection
 * @param future [in] The future resolved when a response is ready
 * @param method [in] The CoAP method designator string
 * @param path [in] The URI path element of the resource being requested
 * @param contentFormat [in] The content format of the payload or 0 on no payload.
 * @param payload [in] The payload of the request or NULL for no payload
 * @param payloadLenth [in] The length of the payload.
 * @param response [out] The resulting response if the future resolves with OK.
 * @return NABTO_DEVICE_EC_OK iff successful
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API nabto_device_virtual_connection_coap_invoke(NabtoDeviceVirtualConnection* connection, NabtoDeviceFuture* future, const char* method, const char* path, uint16_t contentFormat, const void* payload, size_t payloadLength, NabtoDeviceVirtualCoapResponse* response);

/**
 * Free a virtual CoAP response when done handling it.
 *
 * @param response [in]  Response to be freed
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_virtual_coap_response_free(NabtoDeviceVirtualCoapResponse* response);

/**
 * Get response status. encoded as e.g. 404, 200, 203, 500.
 *
 * @param coap [in] the coap response object.
 * @param statusCode [out]  the statusCode for the request
 * @retval NABTO_DEVICE_EC_OK if the status code exists.
 * @retval NABTO_DEVICE_EC_INVALID_STATE if there's no response yet.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_coap_get_response_status_code(NabtoDeviceVirtualCoapResponse* coap, uint16_t* statusCode);

/**
 * Get content type of the payload if one exists.
 *
 * @param coap [in] The coap response object.
 * @param contentType [out] The content type if it exists.
 * @retval NABTO_DEVICE_EC_OK iff response has a contentFormat
 * @retval NABTO_DEVICE_EC_NO_DATA if the response does not have a content format
 * @retval NABTO_DEVICE_EC_INVALID_STATE if no response is ready
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_coap_get_response_content_format(NabtoDeviceVirtualCoapResponse* coap, uint16_t* contentType);

/**
 * Get the coap response data.
 *
 * The payload is available until nabto_device_coap_free is called.
 *
 * @param coap [in] the coap response object.
 * @param payload [out] start of the payload.
 * @param payloadLength [out] length of the payload
 * @retval NABTO_DEVICE_EC_OK if a payload exists and payload and payloadLength is set appropriately.
 * @retval NABTO_DEVICE_EC_NO_DATA if the response does not have a payload
 * @retval NABTO_DEVICE_EC_INVALID_STATE if no response is ready yet.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_coap_get_response_payload(NabtoDeviceVirtualCoapResponse* coap, void** payload, size_t* payloadLength);



typedef struct NabtoDeviceVirtualStream_ NabtoDeviceVirtualStream;


/**
 * Create a virtual stream.
 *
 * @param connection [in]  The virtual connection to make the stream on, the connection needs
 * to be kept alive until the stream has been freed.
 * @return  NULL if the stream could not be created, non NULL otherwise.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceVirtualStream* NABTO_DEVICE_API
nabto_device_virtual_stream_new(NabtoDeviceVirtualConnection* connection);

/**
 * Free a virtual stream. If a stream has unresolved futures when freed, they
 * may not be resolved. For streams with outstanding futures, call
 * nabto_device_virtual_stream_abort(), and free the stream when all futures
 * are resolved.
 *
 * @param stream [in]  The virtual stream to free
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_virtual_stream_free(NabtoDeviceVirtualStream* stream);

/**
 * Read exactly bufferLength bytes from a virtual stream.
 *
 * if (readLength != bufferLength) the stream has reached a state
 * where no more bytes can be read.
 *
 * Future status:
 *  - NABTO_DEVICE_EC_OK   if all data was read.
 *  - NABTO_DEVICE_EC_EOF  if only some data was read and the stream is eof.
 *  - NABTO_DEVICE_EC_ABORTED if the stream is aborted.
 *  - NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if stream is already being read
 *
 * @param stream [in]         The virtual stream to read bytes from.
 * @param future [in]         Future to resolve with the result of the operation.
 * @param buffer [out]        The output buffer to put data into.
 * @param bufferLength [in]   The length of the output buffer and number of bytes to read.
 * @param readLength [out]    The actual number of bytes read.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_virtual_stream_read_all(NabtoDeviceVirtualStream* stream,
                             NabtoDeviceFuture* future,
                             void* buffer,
                             size_t bufferLength,
                             size_t* readLength);

/**
 * Read some bytes from a virtual stream.
 *
 * Read atleast 1 byte from the stream, unless an error occurs or the
 * stream is eof.
 *
 * Future status:
 *  - NABTO_DEVICE_EC_OK if some bytes was read.
 *  - NABTO_DEVICE_EC_EOF if stream is eof.
 *  - NABTO_DEVICE_EC_ABORTED if the stream is aborted.
 *  - NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if stream is already being read
 *
 * @param stream [in]         The virtual stream to read bytes from.
 * @param future [in]         Future to resolve with the result of the operation.
 * @param buffer [out]        The output buffer to put data into.
 * @param bufferLength [out]  The length of the output buffer and max bytes to read.
 * @param readLength [out]    The actual number of bytes read.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_virtual_stream_read_some(NabtoDeviceVirtualStream* stream,
                              NabtoDeviceFuture* future,
                              void* buffer,
                              size_t bufferLength,
                              size_t* readLength);

/**
 * Write bytes to a virtual stream.
 *
 * @param stream [in]        The stream to write data to.
 * @param buffer [in]        The input buffer with data to write to the stream.
 * @param bufferLength [in]  Length of the input data.
 * @retval NABTO_DEVICE_EC_OK on success
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_stream_write(NabtoDeviceVirtualStream* stream,
                          const void* buffer,
                          size_t bufferLength);

/**
 * Close a stream. When a stream has been closed no further data can
 * be written to the stream. Data can however still be read from the
 * stream until the other peer closes the stream.
 *
 * @param stream [in]  The stream to close.
 * @retval NABTO_DEVICE_EC_OK on success.
 */

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_stream_close(NabtoDeviceVirtualStream* stream);

/**
 * Abort a stream. When a stream is aborted, all unresolved futures
 * will be resolved. Once all futures are resolved
 * nabto_device_virtual_stream_free() can be called.
 *
 * @param stream [in]   The stream to abort.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_virtual_stream_abort(NabtoDeviceVirtualStream* stream);



#ifdef __cplusplus
} // extern c #endif
#endif

#endif
