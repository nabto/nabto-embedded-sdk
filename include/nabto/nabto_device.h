#ifndef _NABTO_DEVICE_H_
#define _NABTO_DEVICE_H_

/**
 * Nabto Device High Level C Api.
 *
 * Nabto provides a platform for connecting applications with
 * devices. The platform consists of three major parts. 
 *
 * Vocabulary:
 *
 * Client: Clients are often apps where the nabto_client library is
 * embedded inside. The clients can make connections to devices. Using
 * the servers.
 *
 * Device: Devices is often embedded devices running the Nabto
 * Embedded SDK, e.g. a heating control system or an ip camera. A
 * device instance can be created by this api.
 *
 * Server: Servers are hosted in datacenters and makes it possible to
 * create connections between the clients and devices.
 */

#if defined(_WIN32)
#define NABTO_DEVICE_API __stdcall
#if defined(NABTO_DEVICE_WIN32_API_STATIC)
#define NABTO_DEVICE_DECL_PREFIX extern
#elif defined(NABTO_DEVICE_CLIENT_API_EXPORTS)
#define NABTO_DEVICE_DECL_PREFIX __declspec(dllexport)
#else
#define NABTO_DEVICE_DECL_PREFIX __declspec(dllimport)
#endif
#else
#define NABTO_DEVICE_API
#define NABTO_DEVICE_DECL_PREFIX extern
#endif

#include <platform/np_error_code.h>

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The NabtoDevice is a the place which owns the device id,
 * sockets, etc.
 */
typedef struct NabtoDevice_ NabtoDevice;

/**
 * The NabtoDeviceConnection represents a connection between a client
 * and device.
 */
typedef struct NabtoDeviceConnection_ NabtoDeviceConnection;

/**
 * The NabtoDeviceStream represents a stream on top of a connection.
 */
typedef struct NabtoDeviceStream_ NabtoDeviceStream;

/**
 * The NabtoDeviceError represents error codes 
 */
typedef np_error_code NabtoDeviceError;

/**
 * The NabtoDeviceFuture is used to resolve asyncronous function calls
 */
typedef struct NabtoDeviceFuture_ NabtoDeviceFuture;


typedef uint32_t nabto_device_duration_t;


enum NabtoDeviceLogLevel_ {
    NABTO_DEVICE_TRACE = 0
};

/**********************
 * Device Api *
 **********************/

/**
 * Create a new device instance.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDevice* NABTO_DEVICE_API
nabto_device_new();

/**
 * Free a device instance
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_free(NabtoDevice* device);

/**
 * Set the product id
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_product_id(NabtoDevice* device, const char* productId);

/**
 * Set the device id.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_device_id(NabtoDevice* device, const char* deviceId);

/**
 * Set the server url.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_server_url(NabtoDevice* device, const char* serverUrl);

/**
 * Set the public key for the device.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_public_key(NabtoDevice* device, const char* pubKey);

/**
 * Set the private key from the device.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_private_key(NabtoDevice* device, const char* privKey);

/**
 * Set the application name of the device.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_app_name(NabtoDevice* device, const char* name);

/**
 * Set the application version the device.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_app_version(NabtoDevice* device, const char* version);

/**
 * Start the context, attach to some servers if possible, wait for
 * client connections.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_start(NabtoDevice* device);

/**
 * Close a context.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceFuture* NABTO_DEVICE_API
nabto_device_close(NabtoDevice* device);

/**************
 * Connection *
 **************/

/* /\** */
/*  * Listen for new connections. */
/*  *\/ */
/* NABTO_DEVICE_DECL_PREFIX NabtoDeviceFuture* NABTO_DEVICE_API */
/* nabto_device_connection_listen(NabtoDevice* device, NabtoDeviceConnection** connection); */

/* nabto_device_connection_free(NabtoDeviceConnection* connection); */

/* nabto_device_connection_close(NabtoDeviceConnection* connection); */

/* nabto_device_connection_get_client_fingerprint(NabtoDeviceConnection* connection); */
    
/*************
 * Streaming *
 *************/

/**
 * listen for a stream, the returned NabtoDeviceStream* should be
 * freed after use.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceFuture* NABTO_DEVICE_API
nabto_device_stream_listen(NabtoDevice* device, NabtoDeviceStream** stream);

/**
 * Free a stream
 *
 * @param stream, the stream to free
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_stream_free(NabtoDeviceStream* stream);

/**
 * Accept a stream. After a stream is returned from listen, if the
 * stream is accepted this function is called.
 *
 * @param stream, the stream to accept
 * @return a future when resolved the stream is either established or failed.
 *
 * Future status:
 *   NABTO_DEVICE_OK if opening went ok.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceFuture* NABTO_DEVICE_API
nabto_device_stream_accept(NabtoDeviceStream* stream);

/**
 * Read exactly n bytes from a stream
 *
 * if (readLength != bufferLength) the stream has reached a state
 * where no more bytes can be read.
 *
 * @param stream, the stream to read bytes from.
 * @param buffer, the buffer to put data into.
 * @param bufferLength, the length of the output buffer.
 * @param readLength, the actual number of bytes read.
 * @return  a future which resolves with ok or an error.
 *
 * Future status:
 *  NABTO_DEVICE_OK   if all data was read.
 *  NABTO_DEVICE_STREAM_EOF  if only some data was read and the stream is eof.
 *  NABTO_DEVICE_STREAM_ABORTED if the stream is aborted.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceFuture* NABTO_DEVICE_API
nabto_device_stream_read_all(NabtoDeviceStream* stream, void* buffer, size_t bufferLength, size_t* readLength);

/**
 * Read some bytes from a stream.
 *
 * Read atleast 1 byte from the stream, unless an error occurs or the
 * stream is eof.
 *
 * @param stream        The stream to read bytes from
 * @param buffer        The buffer where bytes is copied to,
 * @param bufferLenght  The length of the output buffer
 * @param readLength    The actual number of read bytes.
 * @return  a future which resolves to ok or a stream error.
 *
 * Future status:
 *  NABTO_DEVICE_OK if some bytes was read.
 *  NABTO_DEVICE_STREAM_EOF if stream is eof.
 *  NABTO_DEVICE_STREAM_ABORTED if the stream is aborted.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceFuture* NABTO_DEVICE_API
nabto_device_stream_read_some(NabtoDeviceStream* stream, void* buffer, size_t bufferLength, size_t* readLength);

/**
 * Write bytes to a stream.
 *
 * When the future resolves the data is only written to the stream,
 * but not neccessary acked. This is why it does not make sense to
 * return a number of actual bytes written in case of error since it
 * says nothing about the number of acked bytes. To ensure that
 * written bytes have been acked, a succesful call to
 * nabto_device_stream_close is neccessary after last call to
 * nabto_device_stream_write.
 * 
 * @param stream, the stream to write data to.
 * @param buffer, the input buffer with data to write to the stream.
 * @param bufferLenth, length of the input data.
 * @return a future when resolved the data is written to the stream.
 *
 * Future status:
 *  NABTO_DEVICE_OK if write was ok.
 *  NABTO_DEVICE_STREAM_CLOSED if the stream is closed for writing.
 *  NABTO_DEVICE_STREAM_ABORTED if the stream is aborted.
 * 
 * TODO clarify what happens when a stream is closed while a call to write is in progress.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceFuture* NABTO_DEVICE_API
nabto_device_stream_write(NabtoDeviceStream* stream, const void* buffer, size_t bufferLength);

/**
 * Close a stream. When a stream has been closed no further data can
 * be written to the stream. Data can however still be read from the
 * stream until the other peer closes the stream.
 *
 * When close returns all written data has been acknowledged by the
 * other peer.
 * 
 * @param stream, the stream to close.
 *
 * Future status:
 *  NABTO_DEVICE_STREAM_OK if the stream is closed for writing.
 *  NABTO_DEVICE_STREAM_ABORTED if the stream is aborted.
 */

NABTO_DEVICE_DECL_PREFIX NabtoDeviceFuture* NABTO_DEVICE_API
nabto_device_stream_close(NabtoDeviceStream* stream);

/**************
 * Future API *
 **************/

/**
 * We have made a future api such that it's easier to get all the
 * different async models from a simple standard api.
 *
 * We could have implemented all the future functions for each async
 * function but that would lead to a lot of specialized functions
 * doing almost the same thing.
 */

/**
 * Callback function for resolving futures.
 */
typedef void (*NabtoDeviceFutureCallback)(NabtoDeviceError err, void* data);

/**
 * Free a future.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_future_free(NabtoDeviceFuture* future);

/**
 * Query if a future is ready.
 *
 * @param future, the future.
 * @return NABTO_DEVICE_OK if the future is ready else NABTO_DEVICE_API_FUTURE_NOT_READY
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_future_ready(NabtoDeviceFuture* future);

/**
 * Set a callback to be called when the future resolves
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_future_set_callback(NabtoDeviceFuture* future,
                                 NabtoDeviceFutureCallback callback,
                                 void* data);
/**
 * Wait until a future is resolved.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_future_wait(NabtoDeviceFuture* future);

/**
 * Wait atmost duration milliseconds for the future to be resolved.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_future_timed_wait(NabtoDeviceFuture* future, nabto_device_duration_t duration);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_future_error_code(NabtoDeviceFuture* future);

/*************
 * Error API *
 *************/

// TODO
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_error_get_message(NabtoDeviceError error);

/********
 * Misc *
 ********/

/**
 * Return the version of the nabto client library.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_version();

/***********
 * Logging *
 ***********/

typedef void (*NabtoDeviceLogCallback)(const char* logLine, void* data);
typedef enum NabtoDeviceLogLevel_ NabtoDeviceLogLevel;

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_log_callback(NabtoDeviceLogCallback cb, void* data);

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_log_level(NabtoDeviceLogLevel level);


#ifdef __cplusplus
} // extern c
#endif

#endif
