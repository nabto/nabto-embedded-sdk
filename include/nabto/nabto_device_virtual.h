#ifndef _NABTO_DEVICE_VIRTUAL_H_
#define _NABTO_DEVICE_VIRTUAL_H_

#include "nabto_device.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif




    /// VIRTUAL CLIENT CONNECTIONS ////
    typedef struct NabtoDeviceVirtualConnection_ NabtoDeviceVirtualConnection;

    /**
     * Allocate new Virtual Connection.
     *
     * @param device [in] The device context
     * @return The created virtual connection or NULL on failure
     */
    NABTO_DEVICE_DECL_PREFIX NabtoDeviceVirtualConnection* NABTO_DEVICE_API
        nabto_device_virtual_connection_new(NabtoDevice* device);

    /**
     * Free a previously allocated virtual connection.
     * @param connection [in] The connection to free.
     */
    NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
        nabto_device_virtual_connection_free(NabtoDeviceVirtualConnection* connection);


    /**
     * Close a virtual connection.
     *
     * @param connection [in] The connection to close.
     * @param future [in] Future resolved when the connection is closed
     */
    NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
        nabto_device_virtual_connection_close(NabtoDeviceVirtualConnection* connection, NabtoDeviceFuture* future);

    /**
     * Set a device fingerprint on a virtual connection.
     *
     * The fingerprint is copied into the virtual connection.
     *
     * @param connection [in] The connection to close.
     * @param fp [in] Fingerprint to set.
     * @retval NABTO_DEVICE_EC_OK on success
     */
    NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
        nabto_device_virtual_connection_set_device_fingerprint(NabtoDeviceVirtualConnection* connection, const char* fp);

    /**
     * Set a client fingerprint on a virtual connection.
     *
     * The fingerprint is copied into the virtual connection.
     *
     * @param connection [in] The connection to close.
     * @param fp [in] Fingerprint to set.
     * @retval NABTO_DEVICE_EC_OK on success
     */
    NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
        nabto_device_virtual_connection_set_client_fingerprint(NabtoDeviceVirtualConnection* connection, const char* fp);

    /**
     * Get the connection reference of a virtual connection.
     *
     * @param connection [in]  The virtual connection to get reference for
     * @return The connection reference of the provided virtual connection.
     */
    NABTO_DEVICE_DECL_PREFIX NabtoDeviceConnectionRef  NABTO_DEVICE_API
        nabto_device_connection_get_connection_ref(NabtoDeviceVirtualConnection* connection);


    /**
     * Test if the connection is virtual.
     *
     * @param device [in]  The device
     * @param ref [in]     The connection reference to query
     * @return true iff the connection is virtual.
     */
    NABTO_DEVICE_DECL_PREFIX bool NABTO_DEVICE_API
        nabto_device_connection_is_virtual(NabtoDevice* device, NabtoDeviceConnectionRef ref);


    typedef struct NabtoDeviceVirtualCoapRequest_ NabtoDeviceVirtualCoapRequest;

    /**
     * Create a virtual CoAP request.
     *
     * @param connection [in]  The virtual connection to make the CoAP request on, the connection needs
     * to be kept alive until the request has been freed.
     * @return  NULL if the request could not be created, non NULL otherwise.
     */
    NABTO_DEVICE_DECL_PREFIX NabtoDeviceVirtualCoapRequest* NABTO_DEVICE_API
        nabto_device_virtual_coap_request_new(NabtoDeviceVirtualConnection* connection, NabtoDeviceCoapMethod method, const char** segments);

    /**
     * Free a virtual CoAP request when done handling it.
     *
     * @param request [in]  Request to be freed
     */
    NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
        nabto_device_virtual_coap_request_free(NabtoDeviceVirtualCoapRequest* request);


    /**
     * Set the payload of a given virtual CoAP request.
     *
     * @param request [in]   The request on which to set the payload
     * @param data [in]      The payload to set
     * @param dataSize [in]  The length of the payload in bytes
     *
     * @retval NABTO_DEVICE_EC_OK on success
     * @retval NABTO_DEVICE_EC_OUT_OF_MEMORY if payload could not be allocated
     */
    NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
        nabto_device_virtual_coap_request_set_payload(NabtoDeviceVirtualCoapRequest* request,
            const void* data,
            size_t dataSize);

    /**
     * Set the content format of a given virtual CoAP request. This should follow the
     * content format definitions defined by IANA (same as HTTP).
     *
     * @param request [in]   The request to set content format on
     * @param format [in]    The format to set
     * @return NABTO_DEVICE_EC_OK on success
     */
    NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
        nabto_device_virtual_coap_request_set_content_format(NabtoDeviceVirtualCoapRequest* request, uint16_t format);


    /**
     * Execute a virtual CoAP request.
     *
     * @param request [in] The request to execute
     * @param future [in] The future resolved when a response is ready
     * @return NABTO_DEVICE_EC_OK iff successful
     */
    NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
        nabto_device_virtual_coap_request_execute(NabtoDeviceVirtualCoapRequest* request, NabtoDeviceFuture* future);

    /**
     * Get response status. encoded as e.g. 404, 200, 203, 500.
     *
     * @param coap [in] the coap request object.
     * @param statusCode [out]  the statusCode for the request
     * @retval NABTO_DEVICE_EC_OK if the status code exists.
     * @retval NABTO_DEVICE_EC_INVALID_STATE if there's no response yet.
     */
    NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
        nabto_device_virtual_coap_request_get_response_status_code(NabtoDeviceVirtualCoapRequest* coap, uint16_t* statusCode);

    /**
     * Get content type of the payload if one exists.
     *
     * @param coap [in] The coap request object.
     * @param contentType [out] The content type if it exists.
     * @retval NABTO_DEVICE_EC_OK iff response has a contentFormat
     * @retval NABTO_DEVICE_EC_NO_DATA if the response does not have a content format
     * @retval NABTO_DEVICE_EC_INVALID_STATE if no response is ready
     */
    NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
        nabto_device_virtual_coap_request_get_response_content_format(NabtoDeviceVirtualCoapRequest* coap, uint16_t* contentType);

    /**
     * Get the coap response data.
     *
     * The payload is available until nabto_device_coap_free is called.
     *
     * @param coap [in] the coap request object.
     * @param payload [out] start of the payload.
     * @param payloadLength [out] length of the payload
     * @retval NABTO_DEVICE_EC_OK if a payload exists and payload and payloadLength is set appropriately.
     * @retval NABTO_DEVICE_EC_NO_DATA if the response does not have a payload
     * @retval NABTO_DEVICE_EC_INVALID_STATE if no response is ready yet.
     */
    NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
        nabto_device_virtual_coap_request_get_response_payload(NabtoDeviceVirtualCoapRequest* coap, void** payload, size_t* payloadLength);



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
     * @param future [in]        Future to resolve with the result of the operation.
     * @param buffer [in]        The input buffer with data to write to the stream.
     * @param bufferLength [in]  Length of the input data.
     * @retval NABTO_DEVICE_EC_OK on success
     */
    NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
        nabto_device_virtual_stream_write(NabtoDeviceVirtualStream* stream,
            NabtoDeviceFuture* future,
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
