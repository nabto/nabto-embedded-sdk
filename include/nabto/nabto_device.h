#ifndef _NABTO_DEVICE_H_
#define _NABTO_DEVICE_H_

/*
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
#define NABTO_DEVICE_DECL_PREFIX
#elif defined(NABTO_DEVICE_API_EXPORTS)
#define NABTO_DEVICE_DECL_PREFIX __declspec(dllexport)
#else
#define NABTO_DEVICE_DECL_PREFIX __declspec(dllimport)
#endif
#else
#define NABTO_DEVICE_API
#if defined(NABTO_DEVICE_API_SHARED)
#define NABTO_DEVICE_DECL_PREFIX __attribute__((visibility("default")))
#endif
#endif

#ifndef NABTO_DEVICE_DECL_PREFIX
#define NABTO_DEVICE_DECL_PREFIX
#endif


#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The NabtoDevice is an opaque context reference that allows the SDK to keep track of device
 * configuration, resources such as sockets etc. Most operations in this SDK takes place
 * through such a reference.
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
 * The NabtoDeviceListener is used for general listen functionallity
 * throughout the API.
 */
typedef struct NabtoDeviceListener_ NabtoDeviceListener;

/**
 * The NabtoDeviceFuture is used to resolve asyncronous function calls
 */
typedef struct NabtoDeviceFuture_ NabtoDeviceFuture;

/**
 * The nabto_device_duration_t is a time abstraction used to wait for
 * futures.
 */
typedef uint32_t nabto_device_duration_t;

/**
 * Connection reference, used to correlate requests on connections
 * with e.g. IAM systems.
 */
typedef uint64_t NabtoDeviceConnectionRef;

/**
 * Nabto device error codes.
 *
 * ```
 * NABTO_DEVICE_EC_OK
 * NABTO_DEVICE_EC_UNKNOWN
 * NABTO_DEVICE_EC_NOT_IMPLEMENTED
 * NABTO_DEVICE_EC_OUT_OF_MEMORY
 * NABTO_DEVICE_EC_STRING_TOO_LONG
 * NABTO_DEVICE_EC_OPERATION_IN_PROGRESS
 * NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED
 * NABTO_DEVICE_EC_ABORTED
 * NABTO_DEVICE_EC_STOPPED
 * NABTO_DEVICE_EC_EOF
 * NABTO_DEVICE_EC_INVALID_STATE
 * NABTO_DEVICE_EC_INVALID_ARGUMENT
 * NABTO_DEVICE_EC_INVALID_CONNECTION
 * NABTO_DEVICE_EC_NO_DATA
 * NABTO_DEVICE_EC_IN_USE
 * NABTO_DEVICE_EC_ADDRESS_IN_USE
 * NABTO_DEVICE_EC_NOT_ATTACHED
 * ```
 */
typedef int NabtoDeviceError;

/*
 * The NabtoDeviceError represents error codes.
 */
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_OK;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_UNKNOWN;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_NOT_IMPLEMENTED;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_OUT_OF_MEMORY;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_STRING_TOO_LONG;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_OPERATION_IN_PROGRESS;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_ABORTED;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_STOPPED;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_EOF;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_INVALID_STATE;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_INVALID_ARGUMENT;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_INVALID_CONNECTION;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_NO_DATA;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_IN_USE;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_ADDRESS_IN_USE;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceError NABTO_DEVICE_EC_NOT_ATTACHED;


/**********************
 * Device Context API *
 **********************/

/**
 * @intro Device Context
 *
 * The Device Context API manages NabtoDevice instances. This happens through basic lifecycle
 * functions for allocation/deallocation and start/stop. And through functions for configuring all
 * device details.
 */

/**
 * Create a new device instance. If this function succeeds, the user
 * is responsible for cleaning up the returned resource. To properly
 * cleanup the device instance it must be stopped and freed by calling
 * nabto_device_stop() and nabto_device_free().
 *
 * @return the new device instance, NULL on failure
 */
NABTO_DEVICE_DECL_PREFIX NabtoDevice* NABTO_DEVICE_API
nabto_device_new();

/**
 * This function starts the device. It allocates the relevant
 * resources and starts the attach process and makes the device accept
 * connections. When the future resolves the context has been started
 * but the device has not been attached to servers yet. All
 * configuration functions (such as nabto_device_set_device_id) must
 * be called prior to invoke this function.
 *
 * @param device [in]   The device instance to start
 * @param future [in]   The future which is resolved when started.
 * Future error codes:
 *   NABTO_DEVICE_EC_OK on success
 *   NABTO_DEVICE_EC_INVALID_STATE if device does not have public Key,
 *             private key, server URL, device ID, or Product ID.
 *   NABTO_DEVICE_EC_IN_USE  if a resource cannot be allocated because it is already used.
 *   NABTO_DEVICE_EC_ADDRESS_IN_USE  if a socket cannot be bound to an address/port beacause it is already in use.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_start(NabtoDevice* device, NabtoDeviceFuture* future);


/**
 * Close a context. This can be called after nabto_device_start() to
 * close all connections down nicely before calling
 * nabto_device_stop().
 *
 * @param device [in]  The device instance to close.
 * @param future [in]  Future to resolve once the device is closed.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_close(NabtoDevice* device, NabtoDeviceFuture* future);


/**
 * Stop a device. This function blocks until all futures, events and timed
 * events has been handled, and the device core has been stopped.
 *
 * After this function returns, only calls to free functions are allowed. This
 * means that to restart a device, it must be stopped, freed, allocated (with
 * nabto_device_new) and started again.
 *
 * @param device [in]   The device instance to stop
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_stop(NabtoDevice* device);


/**
 * Free a stopped device instance.
 *
 * @param device [in]   The device instance to free
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_free(NabtoDevice* device);

/**
 * Set the product id. Required before calling nabto_device_start().
 *
 * @param device [in]     The device instance to perform action on
 * @param productId [in]  The product ID to set e.g. pr-abcdefg
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if string could not be saved
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_product_id(NabtoDevice* device, const char* productId);

/**
 * Get the product id.
 *
 * @param device [in]  The device
 * @return The product id, or undefined if not set. The pointer
 *         is valid until nabto_device_free is being called.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_get_product_id(NabtoDevice* device);

/**
 * Set the device id. Required before calling nabto_device_start().
 *
 * @param device [in]   The device instance to perform action on
 * @param deviceId [in] The device ID to set e.g. de-abcdefg
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if string could not be saved
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_device_id(NabtoDevice* device, const char* deviceId);

/**
 * Get the device id.
 *
 * @param device [in]  The device
 * @return The device id, or undefined if not set. The pointer
 *         is valid until nabto_device_free is being called.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_get_device_id(NabtoDevice* device);

/**
 * Set the server url. If not set it will default to <Product
 * ID>.devices.nabto.net. Cannot be called after nabto_device_start().
 *
 * @param device [in]    The device instance to perform action on
 * @param serverUrl [in] The url of the basestation attach node to set e.g. foo.bar.baz
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if string could not be saved
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_server_url(NabtoDevice* device, const char* serverUrl);

/**
 * Set the server port. If not set it will default to 443.
 *
 * @param device [in]  The device
 * @param port [in]    The port number to set.
 * @return NABTO_DEVICE_EC_OK on success
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_server_port(NabtoDevice* device, uint16_t port);

/**
 * Set the private key from the device. Required before calling
 * nabto_device_start().
 *
 * @param device [in]   The device instance to perform action on
 * @param privKey [in]  The private key to set
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if string could not be saved
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_private_key(NabtoDevice* device, const char* privKey);

/**
 * Set root certs
 *
 * By default the device is configured to trust "Nabto Root CA
 * 1". This behavior can be overridden by the following function. All
 * trusted root certs should be in the string and be encoded as
 * PEM. The certs are copied into the device so the string can be
 * freed after the call.
 *
 * Root certs are used to validate the connection to the basestation.
 *
 * @param device [in]  The device
 * @param roots [in]  Root certs encoded as pem.
 * @return NABTO_DEVICE_EC_OK iff ok
 *         NABTO_DEVICE_INVALID_STATE if device is started
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_root_certs(NabtoDevice* device, const char* roots);

/**
 * Set the application name of the device. This is used to identify a
 * group of devices in the basestation and the Nabto Cloud Console to
 * ease debugging after deployment.
 *
 * @param device [in]   The device instance to perform action on
 * @param name [in]     The application name to set
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_STRING_TOO_LOG if string length > 32
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_app_name(NabtoDevice* device, const char* name);

/**
 * Get the app name. If the app name is not set, return NULL.
 *
 * This function is not thread safe if set_app_name is called after
 * or at the same time as this call.
 *
 * @param device [in]  The device.
 * @return the app name or NULL if not set.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_get_app_name(NabtoDevice* device);

/**
 * Set the application version the device.
 *
 * @param device [in]   The device instance to perform action on
 * @param version [in]  The application version to set
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_STRING_TOO_LOG if string length > 32
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_app_version(NabtoDevice* device, const char* version);

/**
 * Get the app version. If the app name is not set, return NULL.
 *
 * This function is not thread safe if set_app_version is called after
 * or at the same time as this call.
 *
 * @param device [in]  The device.
 * @return the app version or NULL if not set.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_get_app_version(NabtoDevice* device);

/**
 * The device has two UDP sockets which is used for connection
 * packets. One socket is used solely for local connections and one
 * socket is used for internet facing p2p packets. These sockets are
 * called the local socket and the p2p socket.
 *
 * This function sets the port number which the local socket is bound
 * to. If this function is not called the port number 5592 is used. If
 * this option is set to 0 a free port is choosen by the system.
 *
 * The port needs to be set before the function nabto_device_start() is
 * called.
 *
 * @param device [in]   The device instance to perform action on
 * @param port [in]     The port number to set
 * @return NABTO_DEVICE_EC_OK on success
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_local_port(NabtoDevice* device, uint16_t port);

/**
 * See nabto_device_set_local_port() for a description of local and
 * p2p sockets.
 *
 * This function sets the port number which the p2p socket is bound
 * to. If this function is not called the port number 5593 is used. If
 * this option is set to 0 a free port is choosen by the system.
 *
 * The port needs to be set before the function nabto_device_start() is
 * called.
 *
 * @param device [in]   The device
 * @param port [in]     The port number to bind to
 * @return NABTO_DEVICE_EC_OK on success
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_p2p_port(NabtoDevice* device, uint16_t port);


/**
 * See nabto_device_set_local_port() for a description of local and
 * p2p sockets.
 *
 * Get the port number used by the local socket.
 *
 * @param device [in]   The device instance to perform action on
 * @param port [out]    Reference port to set
 * @return  NABTO_DEVICE_EC_OK on success
 *          NABTO_DEVICE_EC_INVALID_STATE if the socket did not have a port
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_get_local_port(NabtoDevice* device, uint16_t* port);

/**
 * See nabto_device_set_local_port() for a description of local and
 * p2p sockets.
 *
 * Get the port number used by the p2p socket.
 *
 * @param device [in]   The device instance to perform action on
 * @param port [out]    Reference port to set
 * @return  NABTO_DEVICE_EC_OK on success
 *          NABTO_DEVICE_EC_INVALID_STATE if the socket did not have a port
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_get_p2p_port(NabtoDevice* device, uint16_t* port);

/**
 * Utilitiy function to create a private key for a device. Once
 * created, the key should be set on the device using
 * nabto_device_set_private_key(), and freed with
 * nabto_device_string_free() when no longer used.
 *
 * @param device [in]  The device
 * @param key [out]    Where to put the created key
 * @return NABTO_DEVICE_EC_OK on success
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_create_private_key(NabtoDevice* device, char** key);


/**
 * Get the public key fingerprint of the device.  The fingerprint
 * should be freed by calling nabto_device_string_free() afterwards.
 *
 * @param device [in]        The device
 * @param fingerprint [out]  The fingerprint is stored as hex in the parameter.
 * @return NABTO_DEVICE_EC_OK iff the fingerprint is available in the fingerprint output parameter.
 *         NABTO_DEVICE_EC_INVALID_STATE if the device provided did not contain a valid private key.
 *         NABTO_DEVICE_EC_UNKNOWN on underlying DTLS module error
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_get_device_fingerprint(NabtoDevice* device, char** fingerprint);

/**
 * Get a truncated fingerprint of the device public key.
 * @deprecated
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_get_device_fingerprint_hex(NabtoDevice* device, char** fingerprint);

/**
 * Same as nabto_device_get_device_fingerprint.
 * @deprecated
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_get_device_fingerprint_full_hex(NabtoDevice* device, char** fingerprint);

/**
 * Enable/disable basestation attach. When disabled, the device will not attempt to connect to the
 * Nabto Basestation and clients will only be able to connect to the device directly (local
 * connection using mdns discovery or with direct candidates). This function can be called both
 * before and after nabto_device_start(), but not after nabto_device_close(). If uncalled before
 * nabto_device_start() attach will default to enabled.
 *
 * @param device [in]  The device.
 * @param enable [in]  if True the device will attach to the basestation.
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_INVALID_STATE if device closed
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_basestation_attach(NabtoDevice* device, bool enable);

/******************
 * Connection API
 ******************/

/**
 * @intro Connection
 *
 * The Connection API enables the application to get notified on incoming connections and query
 * established connections. Used internally by the Nabto IAM module to provide more abstract access
 * control mechanisms - but can also be used as-is directly by the application.
 */

/**
 * Get the fingerprint of the client assosiated with a given
 * connection. Free fp with nabto_device_string_free().
 *
 * @param device [in]  The device
 * @param ref [in]     The connection reference for which to get finterprint
 * @param fp [out]     Where to put the fingerprint.
 * @return NABTO_DEVICE_EC_OK on success
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_client_fingerprint(NabtoDevice* device,
                                               NabtoDeviceConnectionRef ref,
                                               char** fp);

/**
 * Get the truncated fingerprint of a clients public key.
 * @deprecated
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_client_fingerprint_hex(NabtoDevice* device,
                                                   NabtoDeviceConnectionRef ref,
                                                   char** fp);

/**
 * Same as nabto_device_connection_get_client_fingerprint
 * @deprecated
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_client_fingerprint_full_hex(NabtoDevice* device,
                                                        NabtoDeviceConnectionRef ref,
                                                        char** fp);


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
 * @return true iff local, false otherwise
 */
NABTO_DEVICE_DECL_PREFIX bool NABTO_DEVICE_API
nabto_device_connection_is_local(NabtoDevice* device,
                                 NabtoDeviceConnectionRef ref);

/**
 * Test if the connection is password authenticated.
 *
 * @param device [in]  The device
 * @param ref [in]     The connection reference to query
 * @return true iff the connection is password authenticated.
 */
NABTO_DEVICE_DECL_PREFIX bool NABTO_DEVICE_API
nabto_device_connection_is_password_authenticated(NabtoDevice* device, NabtoDeviceConnectionRef ref);


/**
 * Get the username used for password authentication if it was
 * attempted. The username is set during the authentication process,
 * meaning the username should only be used if a prior call to
 * nabto_device_connection_is_password_authenticated() returned
 * true. The returned string must be freed using
 * nabto_device_string_free().
 *
 * @param device [in]    The device.
 * @param ref    [in]    The connection reference for which to get username.
 * @param username [out] Where to put the username string.
 * @return NABTO_DEVICE_EC_INVALID_CONNECTION iff connection does not exist
 *         NABTO_DEVICE_EC_INVALID_STATE iff password authentication not performed
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY iff string could not be allocated
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_password_authentication_username(NabtoDevice* device, NabtoDeviceConnectionRef ref, char** username);


/**
 * Connection events relevant for the application.
 * ```
 * NABTO_DEVICE_CONNECTION_EVENT_OPENED;
 * NABTO_DEVICE_CONNECTION_EVENT_CLOSED;
 * NABTO_DEVICE_CONNECTION_EVENT_CHANNEL_CHANGED;
 * ```
 */
typedef int NabtoDeviceConnectionEvent;

NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceConnectionEvent NABTO_DEVICE_CONNECTION_EVENT_OPENED;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceConnectionEvent NABTO_DEVICE_CONNECTION_EVENT_CLOSED;
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceConnectionEvent NABTO_DEVICE_CONNECTION_EVENT_CHANNEL_CHANGED;

/**
 * Initialize a listener for connection events.
 *
 * @param device [in]    Device
 * @param listener [in]  Listener to initialize for connection events
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if underlying structure could not be allocated
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_events_init_listener(NabtoDevice* device, NabtoDeviceListener* listener);

/**
 * Start listening for next connection event.
 *
 * @param listener [in]  Listener to get connection events from
 * @param future [in]    Future which resolves when event is ready or on errors.
 * @param ref [out]      Where to put the connection reference when the future resolves.
 * @param event [out]    Where to put the connection event when the future resolves.
 *
 * Future status:
 *   NABTO_DEVICE_EC_OK if event new event is set
 *   NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if listener already have a future
 *   NABTO_DEVICE_EC_OUT_OF_MEMORY if future or and underlying structure could not be allocated
 *   NABTO_DEVICE_EC_ABORTED if underlying service stopped (eg. if device closed)
 *   NABTO_DEVICE_EC_STOPPED if the listener was stopped
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_connection_event(NabtoDeviceListener* listener,
                                       NabtoDeviceFuture* future,
                                       NabtoDeviceConnectionRef* ref,
                                       NabtoDeviceConnectionEvent* event);

/********************
 * Device Events API
 ********************/

/**
 * General events relevant for the application. Events provides information about the device
 * connection to the basestation, ie registration with the Nabto servers. Only when the device is
 * attached to the basestation will remote connections to the device be possible. If the attach
 * procedure fails due to basestation not recognizing the Product ID, Device ID, or Fingerprint
 * configured for the device, an event is also emitted. If the connection to the basestation is
 * lost, a dettached event is emitted. Unless closed by the user, the device will automatically
 * attempt to reattach to the basestation after a non-successful attach.
 *
 * ```
 * NABTO_DEVICE_EVENT_ATTACHED
 * NABTO_DEVICE_EVENT_DETACHED
 * NABTO_DEVICE_EVENT_CLOSED
 * NABTO_DEVICE_EVENT_UNKNOWN_FINGERPRINT
 * NABTO_DEVICE_EVENT_WRONG_PRODUCT_ID
 * NABTO_DEVICE_EVENT_WRONG_DEVICE_ID
 * ```
 */
typedef int NabtoDeviceEvent;

// The device is successfully attached to the basestation.
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceEvent NABTO_DEVICE_EVENT_ATTACHED;

// The device is detached after it has been attached.
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceEvent NABTO_DEVICE_EVENT_DETACHED;

// The device has been closed by a call to nabto_device_close()
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceEvent NABTO_DEVICE_EVENT_CLOSED;

// The device attach attempt failed. The basestation did not recognize the fingerprint
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceEvent NABTO_DEVICE_EVENT_UNKNOWN_FINGERPRINT;

// The device attach attempt failed. The Product ID did not match the fingerprint in the basestation
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceEvent NABTO_DEVICE_EVENT_WRONG_PRODUCT_ID;

// The device attach attempt failed. The Device ID did not match the fingerprint in the basestation
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceEvent NABTO_DEVICE_EVENT_WRONG_DEVICE_ID;

// The device attach attempt failed. The validation of the basestation certificate failed. See the log for more details.
NABTO_DEVICE_DECL_PREFIX extern const NabtoDeviceEvent NABTO_DEVICE_EVENT_CERTIFICATE_VALIDATION_FAILED;


/**
 * Initialize a listener for device events.
 *
 * @param device [in]   Device
 * @param listener [in] The listener to initialize for device events
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if underlying structure could not be allocated
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_device_events_init_listener(NabtoDevice* device, NabtoDeviceListener* listener);

/**
 * Start listening for next device event.
 *
 * @param listener [in]  Listener to get device events from
 * @param future [in]    Future which resolves when event is ready or on errors.
 * @param event [out]    Where to put the device event when the future resolves.
 *
 * Future status:
 *   NABTO_DEVICE_EC_OK if new event is set
 *   NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if listener already have a future
 *   NABTO_DEVICE_EC_OUT_OF_MEMORY if future or and underlying structure could not be allocated
 *   NABTO_DEVICE_EC_ABORTED if underlying service stopped (eg. if device closed)
 *   NABTO_DEVICE_EC_STOPPED if the listener was stopped
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_device_event(NabtoDeviceListener* listener,
                                   NabtoDeviceFuture* future,
                                   NabtoDeviceEvent* event);


/***************
 * Streams API
 ***************/

/**
 * @intro Streams
 *
 * The Streaming API enables exchange of data between client and device on top of a Nabto
 * connection using a socket like abstraction. The stream is reliable and ensures data is received
 * ordered and complete. If either of these conditions cannot be met, the stream will be closed in
 * such a way that it is detectable.
 *
 * Streaming enables tight integration with both the client and device application. For simpler
 * integration of streaming capabilities, consider the [TCP tunnel
 * feature](/developer/api-reference/embedded-device-sdk/tcp_tunnelling/Introduction.html).
 */

/**
 * Initialize a listener for new streams on a given port. A port can
 * only have one listener.
 *
 * @param device [in]    device
 * @param listener [in]  Listener to initialize for streaming
 * @param port [in]      A number describing the id/port of the stream to listen for.
 *                       Think of it as a demultiplexing port number.
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if underlying structure could not be allocated
 *         NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if the port number has an active listener
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_stream_init_listener(NabtoDevice* device,
                                  NabtoDeviceListener* listener,
                                  uint32_t port);

/**
 * Initialize a listener for new streams with ephemeral port number.
 *
 * @param device [in]    device
 * @param listener [in]  Listener to initialize for streaming
 * @param port [out]     Where to put the chosen port number
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if underlying structure could not be allocated
 *         NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if the port number has an active listener
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_stream_init_listener_ephemeral(NabtoDevice* device,
                                            NabtoDeviceListener* listener,
                                            uint32_t* port);

/**
 * Start listening for new streams. The stream resource must be kept
 * alive untill the returned future is resolved.
 *
 * @param listener [in] Listener to get new streams from.
 * @param future [in]   Future which resolves when a new stream is ready, or an error occurs.
 * @param stream [out]  Where to put reference to a new stream. The new stream must be freed by user.
 *
 * Future status:
 *   NABTO_DEVICE_EC_OK on success
 *   NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if listener already have a future
 *   NABTO_DEVICE_EC_OUT_OF_MEMORY if future or and underlying structure could not be allocated
 *   NABTO_DEVICE_EC_ABORTED if underlying service stopped (eg. if device closed)
 *   NABTO_DEVICE_EC_STOPPED if the listener was stopped
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_new_stream(NabtoDeviceListener* listener,
                                 NabtoDeviceFuture* future,
                                 NabtoDeviceStream** stream);

/**
 * Free a stream. If a stream has unresolved futures when freed, they
 * may not be resolved. For streams with outstanding futures, call
 * nabto_device_stream_abort(), and free the stream when all futures
 * are resolved.
 *
 * @param stream [in]  The stream to free
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_stream_free(NabtoDeviceStream* stream);

/**
 * Accept a stream.
 *
 * When a new stream is coming from the listener the stream is not
 * accepted yet. If the application does not want to handle the stream
 * it can just free it, else it has to call accept to finish the
 * handshake. The future returns the status of the handshake.
 *
 * @param stream [in]  the stream to accept
 * @param future [in]  future which resolved when the stream is accepted
 *
 * Future status:
 *   NABTO_DEVICE_EC_OK if opening went ok.
 *   NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if other accept is in progress
 *   NABTO_DEVICE_EC_ABORTED if device is closed
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_stream_accept(NabtoDeviceStream* stream, NabtoDeviceFuture* future);

/**
 * Get a reference to the underlying connection.
 *
 * @param stream [in]  the stream to get connection from
 * @return Connection reference of the stream
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceConnectionRef NABTO_DEVICE_API
nabto_device_stream_get_connection_ref(NabtoDeviceStream* stream);

/**
 * Read exactly bufferLength bytes from a stream.
 *
 * if (readLength != bufferLength) the stream has reached a state
 * where no more bytes can be read.
 *
 * @param stream [in]         The stream to read bytes from.
 * @param future [in]         Future to resolve with the result of the operation.
 * @param buffer [out]        The output buffer to put data into.
 * @param bufferLength [in]   The length of the output buffer and number of bytes to read.
 * @param readLength [out]    The actual number of bytes read.
 *
 * Future status:
 *  NABTO_DEVICE_EC_OK   if all data was read.
 *  NABTO_DEVICE_EC_EOF  if only some data was read and the stream is eof.
 *  NABTO_DEVICE_EC_ABORTED if the stream is aborted.
 *  NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if stream is already being read
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_stream_read_all(NabtoDeviceStream* stream,
                             NabtoDeviceFuture* future,
                             void* buffer,
                             size_t bufferLength,
                             size_t* readLength);

/**
 * Read some bytes from a stream.
 *
 * Read atleast 1 byte from the stream, unless an error occurs or the
 * stream is eof.
 *
 * @param stream [in]         The stream to read bytes from.
 * @param future [in]         Future to resolve with the result of the operation.
 * @param buffer [out]        The output buffer to put data into.
 * @param bufferLength [out]  The length of the output buffer and max bytes to read.
 * @param readLength [out]    The actual number of bytes read.
 *
 * Future status:
 *  NABTO_DEVICE_EC_OK if some bytes was read.
 *  NABTO_DEVICE_EC_EOF if stream is eof.
 *  NABTO_DEVICE_EC_ABORTED if the stream is aborted.
 *  NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if stream is already being read
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_stream_read_some(NabtoDeviceStream* stream,
                              NabtoDeviceFuture* future,
                              void* buffer,
                              size_t bufferLength,
                              size_t* readLength);

/**
 * Write bytes to a stream.
 *
 * When the future resolves the data is only written to the stream,
 * but not neccessary acked. This is why it does not make sense to
 * return a number of actual bytes written in case of error since it
 * says nothing about the number of acked bytes. To ensure that
 * written bytes have been acked, a succesful call to
 * nabto_device_stream_close() is neccessary after last call to
 * nabto_device_stream_write().
 *
 * @param stream [in]        The stream to write data to.
 * @param future [in]        Future to resolve with the result of the operation.
 * @param buffer [in]        The input buffer with data to write to the stream.
 * @param bufferLength [in]  Length of the input data.
 *
 * Future status:
 *  NABTO_DEVICE_EC_OK if write was ok.
 *  NABTO_DEVICE_EC_CLOSED if the stream is closed for writing.
 *  NABTO_DEVICE_EC_ABORTED if the stream is aborted.
 *  NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if stream is already being written to
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_stream_write(NabtoDeviceStream* stream,
                          NabtoDeviceFuture* future,
                          const void* buffer,
                          size_t bufferLength);

/**
 * Close a stream. When a stream has been closed no further data can
 * be written to the stream. Data can however still be read from the
 * stream until the other peer closes the stream.
 *
 * When close resolves all written data has been acknowledged by the
 * other peer.
 *
 * @param stream [in]  The stream to close.
 * @param future [in]  Future to resolve when stream is closed or on error.
 *
 * Future status:
 *  NABTO_DEVICE_OK if the stream is closed for writing.
 *  NABTO_DEVICE_ABORTED if the stream is aborted.
 *  NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if stream is already being closed.
 */

NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_stream_close(NabtoDeviceStream* stream, NabtoDeviceFuture* future);

/**
 * Abort a stream. When a stream is aborted, all unresolved futures
 * will be resolved. Once all futures are resolved
 * nabto_device_stream_free() can be called.
 *
 * @param stream [in]   The stream to abort.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_stream_abort(NabtoDeviceStream* stream);

/************
 * CoAP API
 ************/

/**
 * @intro CoAP
 *
 * The CoAP API allows clients to interact with a Nabto-enabled device through a HTTP REST like
 * request/response mechanism.
 *
 * This API supersedes the Nabto RPC API known from Nabto Micro / Nabto 4 and earlier.
 */

/**
 * Represents the CoAP method for requests and responses
 */
typedef enum {
    NABTO_DEVICE_COAP_GET,
    NABTO_DEVICE_COAP_POST,
    NABTO_DEVICE_COAP_PUT,
    NABTO_DEVICE_COAP_DELETE
} NabtoDeviceCoapMethod;

/**
 * Represents the supported CoAP content formats for requests and responses.
 */
typedef enum  {
    NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8 = 0,
    NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM = 42,
    NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_JSON = 50,
    NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR = 60
} nabto_device_coap_content_format;

/**
 * Represents a CoAP request received from the client
 */
typedef struct NabtoDeviceCoapRequest_ NabtoDeviceCoapRequest;

/**
 * Resource handling callback invoked when a request is available for the resource
 */
typedef void (*NabtoDeviceCoapResourceHandler)(NabtoDeviceCoapRequest* request, void* userData);

/**
 * Initialize listener for a new CoAP resource. Once a CoAP resource is added,
 * incoming requests will resolve futures retrieved through
 * nabto_device_listener_new_coap_request(). There should never be more than one
 * listener for the same combination of method and pathSegments. The following
 * resources and all their sub-resources are reserved by Nabto:
 *
 * - {"p2p", NULL}
 * - {"tcp-tunnels", NULL}
 * - {"iam", NULL}
 *
 * @param device [in]      The device
 * @param listener [in]    The listener to initialize as CoAP.
 * @param method [in]      The CoAP method for which to handle requests
 * @param pathSegments [in]
 *
 * The CoAP path segments of the resource. The array of segments is a
 * NULL terminated array of null terminated strings. The familiar
 * notation for rest resources "/heatpump/state" becomes the array
 * {"heatpump", "state", NULL }
 *
 * Parameters can be defined by using the syntax {<parameter>} for a
 * parameter. E.g. {"iam","users","{id}",NULL}
 *
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if underlying structure could not be allocated
 *         NABTO_DEVICE_EC_INVALID_ARGUMENT on invalid pathSegment parameter
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError  NABTO_DEVICE_API
nabto_device_coap_init_listener(NabtoDevice* device,
                                NabtoDeviceListener* listener,
                                NabtoDeviceCoapMethod method,
                                const char** pathSegments);

/**
 * Listen for a new coap request on the given listener.
 *
 * @param listener [in]   Listener on which to listen
 * @param future [in]     Future which resolves when a new request is available or an error occurs
 * @param request [out]   Where to reference an incoming request
 *
 * Future status:
 *   NABTO_DEVICE_EC_OK if request is ready
 *   NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if the resource already has an active listener
 *   NABTO_DEVICE_EC_ABORTED if device is being freed
 *   NABTO_DEVICE_EC_STOPPED if the listener has been stopped
 *   NABTO_DEVICE_EC_OUT_OF_MEMORY if request was received but the
 *                                structure could not be allocated.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_new_coap_request(NabtoDeviceListener* listener,
                                       NabtoDeviceFuture* future,
                                       NabtoDeviceCoapRequest** request);


/**
 * Free a CoAP request when done handling it. If called without prior
 * call to nabto_device_coap_error_response() or
 * nabto_device_coap_response_ready(), an error response with code 500
 * is returned to the client.
 *
 * @param request [in]  Request to be freed
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_coap_request_free(NabtoDeviceCoapRequest* request);

/**
 * Send back an error.
 *
 * A coap error consists of a status code and an error description in
 * UTF8. If more complex errors needs to be returned they have to be
 * constructed using a response.
 *
 * @param request [in]  The request for which to create a response
 * @param code [in]     The status code for the response in standard HTTP
 *                      status code format (eg. 404 for not found)
 * @param message [in]  zero terminated UTF8 string message. If Nabto
 *                      failed to allocated memory for the message, an
 *                      error is returned and no response is sent. If NULL
 *                      is provided as this argument, no memory allocations
 *                      are required.
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if payload could not be allocated
 *         NABTO_DEVICE_EC_ABORTED if the underlying connection was closed
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_coap_error_response(NabtoDeviceCoapRequest* request,
                                 uint16_t code,
                                 const char* message);

/**
 * Set the response code of a given response. This code should follow
 * the standard HTTP status codes (eg. 200 for success).
 *
 * @param request [in]   The request for which to set the response code
 * @param code [in]      The code to be set
 *
 * @return NABTO_DEVICE_EC_OK on success
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_coap_response_set_code(NabtoDeviceCoapRequest* request, uint16_t code);

/**
 * Set the payload of a given response.
 *
 * @param request [in]   The request on which to set the response payload
 * @param data [in]      The payload to set
 * @param dataSize [in]  The length of the payload in bytes
 *
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if payload could not be allocated
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_coap_response_set_payload(NabtoDeviceCoapRequest* request,
                                       const void* data,
                                       size_t dataSize);

/**
 * Set the content format of a given response. This should follow the
 * content format definitions defined by IANA (same as HTTP).
 *
 * @param request [in]   The request to set response content format on
 * @param format [in]    The format to set
 *
 * @return NABTO_DEVICE_EC_OK on success
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_coap_response_set_content_format(NabtoDeviceCoapRequest* request, uint16_t format);

/**
 * Mark a response as ready. Once ready, the response will be sent to
 * the client. If a previous call to
 * nabto_device_coap_response_set_payload() returned with an error,
 * setting the response ready will still send the response to the
 * client but with an empty payload.
 *
 * @param request [in]  The request to respond to
 *
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_ABORTED if underlying connection was closed
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_coap_response_ready(NabtoDeviceCoapRequest* request);

/**
 * Get the content format of a given request.
 *
 * @param request [in]        The request for which to get the content format
 * @param contentFormat [out] A reference to where to put the content format
 *
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_NO_DATA if the content format is not available
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_coap_request_get_content_format(NabtoDeviceCoapRequest* request,
                                             uint16_t* contentFormat);

/**
 * Get the payload of a given request.
 *
 * @param request [in]         The request for which to get the payload
 * @param payload [out]        A reference to where to put the payload reference
 * @param payloadLength [out]  A reference to where to put the length of the payload
 *
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_NO_DATA if the request does not contain a payload.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_coap_request_get_payload(NabtoDeviceCoapRequest* request,
                                      void** payload,
                                      size_t* payloadLength);

/**
 * Get a reference to the underlying connection on which the request
 * was received.
 *
 * @param request [in]   The request to get connection ref from
 * @return Reference to the connection on success
 *         0 on error
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceConnectionRef NABTO_DEVICE_API
nabto_device_coap_request_get_connection_ref(NabtoDeviceCoapRequest* request);

/**
 * Get a parameter from a coap requests. If the parameter does not
 * exist NULL is returned. The lifetime for the returned value is no
 * longer than the lifetime of the NabtoDeviceCoapRequest.
 *
 * @param request [in]        The request to get parameter from
 * @param parameterName [in]  Zero terminated UTF8 string name of parameter
 * @return reference to parameter value, NULL on errors
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_coap_request_get_parameter(NabtoDeviceCoapRequest* request, const char* parameterName);

/********************
 * FCM notifications
 ********************/

/**
 * @intro FCM Notifications
 *
 * Integration with Firebase Cloud Messaging (FCM) notifications allows the
 * device to send push notifications to clients. The integration is transparent
 * meaning the Nabto platform forwards the provided payload directly to FCM, and
 * so it must follow the format defined by FCM. Sending push notifications
 * requires a Firebase project, detail guide will be provided soon.
 *
 * Sending a notification from the device is initiated by the device creating a
 * NabtoDeviceFcmNotification object. Then the payload and project ID must be
 * set on the object before sending.
 *
 * When the send function is called, the device will send the notification to
 * the Nabto Basestation which forwards it to FCM through its REST API.
 *
 * When FCM has provided a response, the basestation returns the response to the
 * device, and the NabtoDeviceFuture of the send function resolves. Now the FCM
 * status code and response body can be read from the notification
 * object. Finally, the notification object must be freed.
 *
 * To setup FCM in your project, follow the general guidelines from Google. You must allow Nabto to
 * send push notifications through your FCM project:
 *
 * 1. login to the Google Cloud Console
 *
 * 2. Open the "IAM & Admin" page
 *
 * 3. Add the Nabto Edge push service account `sender@nabto-fcm-prod.iam.gserviceaccount.com` as a
 * member with the role “Firebase SDK Provisioning Service Agent”.
 *
 * In the last step, the only permission needed is `cloudmessaging.messages.create` so you can also
 * create a custom role with only this privilege.
 *
 * The Nabto Edge IAM module provides helper functionality to manage FCM tokens and manage
 * subscription categories, see the simple_push example for how to use this on the device side. The
 * IAM documentation at https://docs.nabto.com/developer/api-reference/coap/iam/users-put-user.html
 * describes how the client invokes the IAM module. Also see the full Android client example at
 * https://github.com/nabto/android-simple-push
 */

/**
 * FCM Notification. This is an object holding the FCM notification request and
 * after the basestation api has been invoked the response from the invocation
 * also exists in the object.
 */
typedef struct NabtoDeviceFcmNotification_ NabtoDeviceFcmNotification;

/**
 * Create a new FCM Notification. The returned object must be freed
 * when no longer used, and can not be reused for multiple
 * notifications.
 *
 * @param device [in]  The device
 * @return Non-NULL if the notification was created successfully
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceFcmNotification* NABTO_DEVICE_API
nabto_device_fcm_notification_new(NabtoDevice* device);

/**
 * Free a FCM notification. If called after nabto_device_fcm_send(),
 * the future must be resolved first (by the device finishing handling
 * the notification, or by nabto_device_fcm_stop())
 *
 * @param notification [in]  The notification to free
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_fcm_notification_free(NabtoDeviceFcmNotification* notification);

/**
 * Set the FCM project id on a notification. The project ID must be
 * created and configured in FCM through the guide <Link TBD>. The
 * project ID is copied into the notification.
 *
 * @param notification [in]  The notification to set project ID in
 * @param projectId [in]     The project ID to set
 * @return NABTO_DEVICE_EC_OK iff the project ID was set
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if allocation failed
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_fcm_notification_set_project_id(NabtoDeviceFcmNotification* notification, const char* projectId);

/**
 * Set a JSON document/payload according to the format
 * https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages/send
 *
 * @param notification [in]  The notification to set payload in
 * @param payload [in]       The payload to set
 * @return NABTO_DEVICE_EC_OK iff the payload was set
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if allocation failed
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_fcm_notification_set_payload(NabtoDeviceFcmNotification* notification, const char* payload);

/**
 * Send a notification.
 *
 * The future returns NABTO_DEVICE_EC_OK iff the invocation of the
 * basestation went OK. A successful invocation of the basestation
 * does not mean a successful invocation of FCM. On OK, the FCM
 * response should evaluated using
 * nabto_device_fcm_notification_get_response_status_code() and
 * nabto_device_fcm_notification_get_response_body(). The response
 * status code is generally enough to determine if a message went OK
 * or not. The response body can be used to get a detailed description
 * in the case an error occurs.
 *
 * @param notification [in]  The notification to send
 * @param future [in]        Future which resolves when sending has been concluded
 *
 * Future resolves with:
 *   NABTO_DEVICE_EC_OK if the notification is delivered to FCM.
 *   NABTO_DEVICE_EC_STOPPED if the operation is stopped.
 *   NABTO_DEVICE_EC_NOT_ATTACHED  if the device is currently not attached to the basestation.
 *   NABTO_DEVICE_EC_INVALID_STATE  if vital data is missing e.g. the project id or the body of the notification.
 *
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_fcm_send(NabtoDeviceFcmNotification* notification, NabtoDeviceFuture* future);

/**
 * Stop an ongoing FCM request. If stop is used there are no guarantee whether a
 * notification has been sent or not sent. It can be used to stop the async
 * operation before it completes or a timeout happens.
 *
 * @param notification [in]  The notification to stop
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_fcm_stop(NabtoDeviceFcmNotification* notification);

/**
 * Get the response status code from the FCM invocation in case the send resolved with NABTO_DEVICE_EC_OK.
 *
 * 200, If the notification was sent ok.
 * 400, If the notification has an invalid format.
 * 403, If the notification could bot be sent due to missing authorization.
 * 404, If the token is expired.
 *
 * See https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode for detailed description of the errors.
 *
 * @param notification [in]  The notification to get status code from
 * @return status code from the FCM request sent by the basestation. 0 if send has not resolved with NABTO_DEVICE_EC_OK
 */
NABTO_DEVICE_DECL_PREFIX uint16_t NABTO_DEVICE_API
nabto_device_fcm_notification_get_response_status_code(NabtoDeviceFcmNotification* notification);

/**
 * Get the response body of the request to FCM. If an error occured
 * this will contain the description. If the send went OK the body
 * will contain a name which is the ID of the sent message. The
 * returned string is valid for the lifetime of the notification
 * object.
 *
 * @param notification [in]  The notification to get response body from
 * @return The response body string. NULL if send has not resolved with NABTO_DEVICE_EC_OK
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_fcm_notification_get_response_body(NabtoDeviceFcmNotification* notification);



/******************
 * TCP Tunnelling
 ******************/

/**
 * @intro TCP Tunnelling
 *
 * TCP tunnelling allows clients to tunnel TCP traffic over a Nabto
 * connection to the device. The TCP Tunnel module uses the
 * Authorization API to determine if actions are allowed on a given
 * connection. An Authorization Request listener must therefore be
 * configured when using TCP tunnelling. It is recomended to use the
 * [Nabto IAM module](/developer/guides/iam/intro.html) to handle
 * Authorization Requests.
 *
 * A TCP tunnel client first makes a CoAP request: `GET
 * /tcptunnels/connect/:serviceId` - this will check that the given
 * connection is authorized to create a connection to the specific TCP
 * Service and return the `StreamPort` the client needs to use for
 * that connection.
 *
 * Later, when a TCP connection is made through the client, a new
 * stream is created to the `StreamPort` obtained in the previous
 * step. When this happens, the device makes another authorization
 * request which again checks that the given connection is allowed to
 * connect to the specific TCP Service.
 *
 * The TCP tunnelling module has the following authorization actions:
 *
 * ```
 * Actions:
 *  TcpTunnel:ListServices  CoAP request to list services
 *  TcpTunnel:GetService    CoAP request to get information for a specific service
 *  TcpTunnel:Connect       See note below
 * ```
 *
 * Note on the `TcpTunnel:Connect` action: When used in CoAP context,
 * it is used to test permissions for establishing a stream connection
 * and to get information about the connection. When used in Streaming
 * context, it is used to authorize an actual stream connection.
 *
 * The TCP Tunnelling module has the following authorization attributes:
 *
 * ```
 * Attributes:
 *   TcpTunnel:ServiceId   The id of the service.
 *   TcpTunnel:ServiceType The type of the service.
 * ```
 */

/**
 * Add a TCP tunnel service to the device. Can be invoked multiple times to add multiple services.
 *
 * @param device [in]        The device instance to add TCP tunnel service on
 * @param serviceId [in]     The unique id of the service.
 * @param serviceType [in]   The type of the service, e.g. ssh, rtsp, http,...
 * @param host [in]          The IPv4 address of the host to connect to e.g. "127.0.0.1"
 * @param port [in]          Port number 22, 80, 554 etc
 * @return NABTO_DEVICE_EC_OK  iff the service was added.
 *         NABTO_DEVICE_EC_INVALID_ARGUMENT if the host could not be parsed as IPv4
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if the underlying structure could not be allocated
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_add_tcp_tunnel_service(NabtoDevice* device,
                                    const char* serviceId,
                                    const char* serviceType,
                                    const char* host,
                                    uint16_t port);

/**
 * Remove a tunnel service from the device
 *
 * @param device [in]     The device instance
 * @param serviceId [in]  ID of service to remove
 * @return NABTO_DEVICE_EC_OK if the service was removed
 *         NABTO_DEVICE_EC_NOT_FOUND if the service ID was not found
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_remove_tcp_tunnel_service(NabtoDevice* device, const char* serviceId);

/*************************
 * Server Connect Tokens
 *************************/

/**
 * @intro Server Connect Tokens
 *
 * Server Connect Tokens (SCTs) enable the device to decide who can
 * access it through the server (basestation). The tokens should not
 * be used as the only authorization mechanism but be seen as a filter
 * for which connections is allowed from the Internet to the device,
 * e.g. to prevent DoS attacks on devices.
 */

/**
 * Generate a sufficiently strong random server connect token.
 *
 * The token is NOT added to the system. The resulting token needs to
 * be freed with nabto_device_string_free().
 *
 * @param device [in]              The device instance
 * @param serverConnectToken [out] Where to put to Server Connect Token (SCT)
 * @return NABTO_DEVICE_EC_OK iff the token is created and a reference is put into serverConnectToken
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if the serverConnectToken could not be allocated
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_create_server_connect_token(NabtoDevice* device, char** serverConnectToken);

/**
 * Add a Server Connect Token (SCT) to the server (basestation) which
 * the device uses.
 *
 * @param device [in]             The device instance
 * @param serverConnectToken [in] The utf8 encoded token which is added to the basestation.
 * @return NABTO_DEVICE_EC_OK if the token is added.
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if the token cannot be stored in the device.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_add_server_connect_token(NabtoDevice* device, const char* serverConnectToken);

/**
 * Get synchronization state of the tokens.
 *
 * The future return ok if synchronization went ok or we are not
 * attached such that synchronization is not neccessary.
 *
 * @param device [in]   The device instance
 * @return NABTO_DEVICE_EC_OK if they are synced
 *         NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if they are being synced
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_are_server_connect_tokens_synchronized(NabtoDevice* device);

/**************************
 * Authorization Requests
 **************************/

/**
 * @intro Authorization
 *
 * The Authorization API allows the application to make authorization
 * decisions for the core. That is, the core asks the application to
 * decide if a given authorization request should be allowed or
 * denied. An Authorization request listener must be created to use
 * the TCP Tunnelling feature.
 *
 * The application has access to details from the authorization
 * request through attributes. The connection on which the
 * authorization request takes place is also available for the
 * application, making it possible to retrieve details about the
 * remote peer as input in the authorization decision process.
 *
 * An Authorization request is requesting access to one of the following
 * actions:
 *
 * ```
 * Actions:
 *  TcpTunnel:ListServices  CoAP request to list services
 *  TcpTunnel:GetService    CoAP request to get information for a specific service
 *  TcpTunnel:Connect       CoAP request to test access permissions, or new stream opened on a tunnel
 * ```
 *
 * The Authorization requests `TcpTunnel:GetService` and `TcpTunnel:Connect` actions contains the following
 * attributes:
 *
 * ```
 * Attributes:
 *   TcpTunnel:ServiceId    The id of the service.
 *   TcpTunnel:ServiceType  The type of the service.
 * ```
 */

/**
 * Opaque reference to an authorization request.
 */
typedef struct NabtoDeviceAuthorizationRequest_ NabtoDeviceAuthorizationRequest;

/**
 * Init an authorization request listener to get notifications on
 * incoming authorization requests. This follows the generic listener
 * pattern in the device. Only one authorization listener can exist on
 * the system.
 *
 * @param device [in]   The device instance
 * @param listener [in] The listener to initialize
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY if underlying structure could not be allocated
 *         NABTO_DEVICE_EC_IN_USE if an authorization listener exists
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_authorization_request_init_listener(NabtoDevice* device, NabtoDeviceListener* listener);

/**
 * Start listening for a new authorization request.
 *
 * @param listener [in]   Listener to get new requests from
 * @param future [in]     Future which resolves when a new request is ready
 * @param request [out]   Where the new request is stored when the future resolves.
 *
 * Future status:
 *   NABTO_DEVICE_EC_OK on success
 *   NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if listener already have a future
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_new_authorization_request(NabtoDeviceListener* listener,
                                                NabtoDeviceFuture* future,
                                                NabtoDeviceAuthorizationRequest** request);

/**
 * Free an authorization request. If called without prior call to
 * nabto_device_authorization_request_verdict(), the request will be
 * denied.
 *
 * @param request [in]  The request to free.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_free(NabtoDeviceAuthorizationRequest* request);

/**
 * The application calls this function to inform the core that the
 * authorization request has been allowed or denied. This happens on
 * incoming authorization requests (ie. when the authorization request
 * listener future resolves).
 *
 * @param request [in]  The request to approve or reject
 * @param allowed [in]  The verdict for the request, if true the request is allowed, if false the request is denied.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_verdict(NabtoDeviceAuthorizationRequest* request, bool allowed);

/**
 * Get the action associated with the request.
 *
 * The string should not be freed and the lifetime is limited by the
 * call to nabto_device_authorization_request_free()
 *
 * @param request [in]  The authorization request
 * @return The action string.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_action(NabtoDeviceAuthorizationRequest* request);

/**
 * Get the connection reference this authorization request originates
 * from.
 *
 * @param   request [in]  The authorization request
 * @return  The connection reference, 0 if the connection is gone
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceConnectionRef NABTO_DEVICE_API
nabto_device_authorization_request_get_connection_ref(NabtoDeviceAuthorizationRequest* request);

/**
 * Get the number of attributes this authorization request contains.
 *
 * @param   request [in]  The authorization request
 * @return  The number of attributes the request contains.
 */
NABTO_DEVICE_DECL_PREFIX size_t NABTO_DEVICE_API
nabto_device_authorization_request_get_attributes_size(NabtoDeviceAuthorizationRequest* request);

/**
 * Get attribute name
 *
 * @param request [in]  The authorization request
 * @param index [in]    The index of the attribute to return the name of.
 * @return the name of the attribute.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_name(NabtoDeviceAuthorizationRequest* request,
                                                      size_t index);

/**
 * Get string value of an authorization request attribute. The provided index
 * must exist.
 *
 * @param request [in]  The authorization request.
 * @param index [in]    The index of the attribute to get the value of.
 * @return The value for the attribute.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_value(NabtoDeviceAuthorizationRequest* request,
                                                       size_t index);


/******************************
 * Password Authentication API
 ******************************/

/**
 * @intro Password Authentication
 *
 * Password authenticate the client and the device. The password authentication is bidirectional and
 * based on PAKE, such that both the client and the device learns that the other end knows the
 * password, without revealing the password to the other end. Only one password authentication
 * listener can exist on the system. The Nabto IAM module can be used to handle password
 * authorization requests.
 *
 * Internally, the Nabto device core supports PAKE through CoAP endpoints. Access to these endpoints
 * are throttled if a client provides an invalid username/password to prevent brute force password
 * cracks. Throttling is done using a token bucket of size 10 and rate 1. This allows 10 incorrect
 * attempts without throttling, after which only 1 attempt pr. second is allowed. After 10 seconds
 * of inactivity, the token bucket is fully replenished. Throttled requests are rejected with status
 * code 429.
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
 * @param device [in]    The device instance.
 * @param listener [in]  The listener to initialize.
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
 * @param listener [in]  The listener to get request from
 * @param future [in]    The future which resolves when a request is ready
 * @param request [in]   The resulting request if the future completes with NABTO_DEVICE_EC_OK
 *
 * Future status:
 *   NABTO_DEVICE_EC_OK on success
 *   NABTO_DEVICE_EC_OPERATION_IN_PROGRESS if listener already have a future
 *   NABTO_DEVICE_EC_ABORTED if underlying service stopped (eg. if device closed)
 *   NABTO_DEVICE_EC_STOPPED if the listener was stopped
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_new_password_authentication_request(NabtoDeviceListener* listener, NabtoDeviceFuture* future, NabtoDevicePasswordAuthenticationRequest** request);

/**
 * Get the username used in the password authentication request. The
 * lifetime of the returned username is until
 * nabto_device_password_authentication_request_free() is called.
 *
 * @param request [in]  The password authorization request
 * @return The NULL terminated username.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_password_authentication_request_get_username(NabtoDevicePasswordAuthenticationRequest* request);

/**
 * Set password for the request. If no password matching the request
 * is found, supply NULL as the password. If NULL is provided, the
 * password authentication protocol continues such that the client
 * does not know if the request failed because of the username or the
 * password being invalid. The password pointer is not used after the
 * call returns.
 *
 * @param request [in]   The password authentication request
 * @param password [in]  NULL terminated password string
 * @return NABTO_DEVICE_EC_OK iff the password was set
 *         NABTO_DEVICE_EC_INVALID_STATE if the function is called multiple times on the same request
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_password_authentication_request_set_password(NabtoDevicePasswordAuthenticationRequest* request, const char* password);

/**
 * Free a password authentication request.
 *
 * Before this function is called a password should be set for the
 * request. If no password was set the effect is the same as setting
 * the password to NULL in
 * nabto_device_password_authentication_request_set_password().
 *
 * @param request [in]  The password authentication request
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API nabto_device_password_authentication_request_free(NabtoDevicePasswordAuthenticationRequest* request);

/**************
 * Futures API
 **************/

/**
 * @intro Futures
 *
 * Nabto Edge uses `Futures` to manage return values and completion of
 * asynchronous API-functions; a future resolves once such function
 * has completed. For more details about this topic, see the [Futures
 * Guide](/developer/guides/overview/nabto_futures.html).
 *
 * Futures are introduced to unify the way return values and
 * completion of asynchronous functions are handled and to minimize
 * the number of specialized functions required in the APIs: Instead
 * of having an asynchronous and synchronous version of all functions,
 * the API instead provides a single version returning a future: For
 * asynchronous behavior, a callback can then be configured on the
 * future - for synchronous behavior, the future provides a `wait`
 * function.
 *
 * In addition to futures, asynchronous functions that are expected to
 * be invoked recurringly introduces the concept of `listeners`, also
 * elaborated in the [Futures
 * Guide](/developer/guides/overview/nabto_futures.html).
 */

/**
 * Callback function for resolving futures.
 */
typedef void (*NabtoDeviceFutureCallback)(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data);

/**
 * Create a new future.
 *
 * A future can be reused for multiple async operation calls. But it
 * may never be reused before the previous usage has
 * resolved. E.g. wait or the callback has returned or the future is
 * polled to not being in the state
 * NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED.
 *
 * @param device [in]  The device instance
 * @return Non-NULL iff the future was created appropriately.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceFuture* NABTO_DEVICE_API
nabto_device_future_new(NabtoDevice* device);

/**
 * Free a future. Free must never be called on an unresolved future.
 *
 * @param future [in]  The future to free.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_future_free(NabtoDeviceFuture* future);

/**
 * Query if a future is ready.
 *
 * @param future [in]  The future.
 * @return NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED if the future is not resolved yet, else the error
 * code of the async operation.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_future_ready(NabtoDeviceFuture* future);

/**
 * Set a callback to be called when the future resolves
 *
 * The callback needs to be set after the async operation has been
 * started.
 *
 * Valid example:
 * nabto_device_stream_read_some(stream, future, ....);
 * nabto_device_future_set_callback(future, ...);
 *
 * INVALID USAGE:
 * nabto_device_future_set_callback(future, ...);
 * nabto_device_stream_read_some(stream, future, ....);
 *
 * @param future [in]   The future instance to set callback on
 * @param callback [in] The function to be called when the future resolves
 * @param data [in]     Void pointer passed to the callback when invoked
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_future_set_callback(NabtoDeviceFuture* future,
                                 NabtoDeviceFutureCallback callback,
                                 void* data);
/**
 * Wait until a future is resolved.
 *
 * This function must not be called before the async operation has
 * been started.
 *
 * Valid example:
 * nabto_device_stream_read_some(stream, future, ....);
 * nabto_device_future_wait(future);
 *
 * @param future [in]  The future to wait for
 * @return the error code of the async operation
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_future_wait(NabtoDeviceFuture* future);

/**
 * Wait atmost duration milliseconds for the future to be resolved.
 *
 * This function must not be called before the async operation has
 * been started.
 *
 * Valid example:
 * nabto_device_stream_read_some(stream, future, ....);
 * nabto_device_future_timed_wait(future, 42);
 *
 * @param future [in]    The future to wait for
 * @param duration [in]  The maximum time to wait in milliseconds
 * @return NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED if the future was
 *         not resolved within the given time. If the future is
 *         ready, the return value is whatever the underlying
 *         function returned.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_future_timed_wait(NabtoDeviceFuture* future, nabto_device_duration_t duration);

/**
 * Get the error code of the resolved future, if the future is not
 * resolved, NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED is returned.
 *
 * @param future [in]  The future.
 * @return NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED if the future was
 *         not resolved. If the future is ready, the return value
 *         is whatever the underlying function returned.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_future_error_code(NabtoDeviceFuture* future);

/****************
 * Listener API
 ****************/

/**
 * @intro Listeners
 *
 * Nabto Edge uses `Futures` to manage return values and completion of asynchronous API-functions; a
 * future resolves once such function has completed. Additionally, the Listener API supports
 * asynchronous functions that are expected to be invoked recurringly (see the [Futures
 * Guide](/developer/guides/overview/nabto_futures.html) for details).
 *
 * Listeners are created and freed through this general API. Once created, a listener is initialized
 * for use with a specific purpose, e.g. to listen for [incoming coap
 * requests](/developer/api-reference/embedded-device-sdk/coap/nabto_device_coap_init_listener.html),
 * [incoming stream
 * requests](/developer/api-reference/embedded-device-sdk/streaming/nabto_device_stream_init_listener.html)
 * or [general device
 * events](/developer/api-reference/embedded-device-sdk/context/nabto_device_device_events_init_listener.html).
 */

/**
 * Create a new listener. After creation, a listener should be initialized for a
 * purpose (e.g. as a stream listener through
 * nabto_device_stream_init_listener()). Once initialized, a listener can only
 * be used for the purpose for which it was initialized.
 *
 * @param device [in]  The device instance
 * @return The created listener, NULL on allocation errors
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceListener* NABTO_DEVICE_API
nabto_device_listener_new(NabtoDevice* device);

/**
 * Free a stopped listener.
 *
 * @param listener [in]  Listener to be freed
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_free(NabtoDeviceListener* listener);

/**
 * Stop a listener, effectivly cancelling active listening on a resource. This
 * will trigger an event with error code NABTO_DEVICE_EC_STOPPED.
 *
 * @param listener [in]  Listener to be stopped
 * @return NABTO_EC_OK on success
 *
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_listener_stop(NabtoDeviceListener* listener);


/**************
 * Logging API
 **************/

/**
 * @intro Logging
 *
 * The logging API allows the application to retrieve log messages from the core SDK and configure
 * the desired core log level. The log callback and level are stored in the Nabto Device as global
 * variables which must be taken into account if multiple Nabto Device instances is running in the
 * same process.
 */

enum NabtoDeviceLogLevel_ {
    NABTO_DEVICE_LOG_FATAL = 0x00000001ul,
    NABTO_DEVICE_LOG_ERROR = 0x00000002ul,
    NABTO_DEVICE_LOG_WARN  = 0x00000004ul,
    NABTO_DEVICE_LOG_INFO  = 0x00000008ul,
    NABTO_DEVICE_LOG_TRACE = 0x00000010ul
};


/**
 * Core SDK log levels.
 *
 * ```
 *   NABTO_DEVICE_LOG_FATAL
 *   NABTO_DEVICE_LOG_ERROR
 *   NABTO_DEVICE_LOG_WARN
 *   NABTO_DEVICE_LOG_INFO
 *   NABTO_DEVICE_LOG_TRACE
 * ```
 */
typedef enum NabtoDeviceLogLevel_ NabtoDeviceLogLevel;


struct NabtoDeviceLogMessage_ {
    NabtoDeviceLogLevel severity;
    const char* file;
    int line;
    const char* message; // the message (null terminated utf-8)
};

/**
 * Log message from core SDK.
 *
 * ```
 * struct NabtoDeviceLogMessage_ {
 *   NabtoDeviceLogLevel severity;
 *   const char* file;
 *   int line;
 *   const char* message; // null (terminated utf-8)
 * }
 * ```
 */
typedef struct NabtoDeviceLogMessage_ NabtoDeviceLogMessage;

/**
 * Log callback function definition. This function is invoked directly
 * by the core when a log message is to be printed. Since this is
 * called directly from the core, blocking or calling back into the
 * API from this function is not allowed.
 */
typedef void (*NabtoDeviceLogCallback)(NabtoDeviceLogMessage* msg, void* data);

/**
 * Set log callback if custom logging is desired. The log callback is stored globally, and so, the
 * device reference is unused. This also means if multiple Nabto Device instances is running in the
 * same process, this function configures the callback for all instances. Since the device reference
 * is unused, this function can be called before `nabto_device_new()` to enable logging of module
 * initialization, particularly useful when integrating a new embedded platform.
 *
 * The log callback can be removed by setting the callback and data to NULL.
 *
 * @param device [in]  The device instance to set callback for
 * @param cb [in]      The function to be called on log event, or NULL to remove
 * @param data [in]    Void pointer passed to the callback when invoked
 * @return NABTO_DEVICE_EC_OK on success
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_log_callback(NabtoDevice* device, NabtoDeviceLogCallback cb, void* data);

/**
 * Set log level of device. The log level is stored globally, and so, the device reference is
 * unused. This also means if multiple Nabto Device instances is running in the same process, this
 * function configures the level for all instances.
 *
 * @param device [in]  The device instance to set level on
 * @param level [in]   The log level to set, available levels are:
 *                     error, warn, info, trace
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_EC_INVALID_ARGUMENT on invalid level string
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_log_level(NabtoDevice* device, const char* level);

/**
 * Set log callback to write logging directly to std out. This configures the log callback to an
 * internally defined function handling the write to std out. As the log callback is stored
 * globally, this is configured for all Nabto Device instances running in the same process. The log
 * callback formats log lines to start with a timestamp, retrieved from the timestamp module of
 * Nabto Device platform. As the callback is stored globally, the Nabto Device platform must remain
 * alive until all Nabto Device instances has stopped using the callback.
 *
 * @param device [in]  The device instance for which to retrieve call log callback invocations.
 * @return NABTO_DEVICE_EC_OK on success
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_log_std_out_callback(NabtoDevice* device);

/**
 * Convert the log level to a string. The returned pointer must not be freed.
 *
 * @param severity [in]  The severity.
 * @return the null terminated string representation of the severity.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_log_severity_as_string(NabtoDeviceLogLevel severity);

/********
 * mDNS
 ********/

/**
 * @intro mDNS
 *
 * The system discovers devices on the local network using mDNS. A
 * device application can either use the built in mDNS functionality
 * or use a third party mDNS implementation. These functions controls
 * the built in mDNS functionality.
 */

/**
 * Enable the optional mDNS server/responder. The server is started when the
 * device is started. mDNS has to be enabled before the device is
 * started. The responder is stopped when the device is closed.
 *
 * @param device [in]  The device instance
 * @return NABTO_DEVICE_EC_OK on success
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_enable_mdns(NabtoDevice* device);

/**
 * Add an additional subtype to the mDNS responses.
 *
 * The subtype <product-id>-<device-id> is added automatically. Other
 * subtypes can be added, such as "heatpump" or "tcptunnel" can be
 * added for easy filtering in the client applications. Subtypes needs
 * to be added before nabto_device_start() is called.
 *
 * @param device [in]   The device instance
 * @param subtype [in]  The subtype to add
 * @return NABTO_DEVICE_EC_OK iff the subtype is added.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_mdns_add_subtype(NabtoDevice* device, const char* subtype);

/**
 * Add additional txt items to the mDNS responses. By default the
 * productid and deviceid is added to mDNS responses.
 *
 * If the device is running when txt records are added the service is
 * unpublished and published again with the new items.
 *
 * If the key already exists it is overwritten with the new value.
 *
 * @param device [in]  The device instance
 * @param key [in]     The txt item key
 * @param value [in]   The txt item value
 * @return NABTO_DEVICE_EC_OK  Iff the txt item was added to the list of txt items
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_mdns_add_txt_item(NabtoDevice* device, const char* key, const char* value);


/*************
 * Service Invocation
 *************/

/**
 * @intro Service Invocation
 *
 * Service invocation is allowing the device to invoke a service which is
 * configured in the basestation. This makes it possible to integrate with
 * services without needing a client initiated connection to the device.
 */
typedef struct NabtoDeviceServiceInvocation_ NabtoDeviceServiceInvocation;

/**
 * Create a new service invocation object.
 *
 * @param device  The device.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceServiceInvocation* NABTO_DEVICE_API
nabto_device_service_invocation_new(NabtoDevice* device);

/**
 * Free a service invocation object
 *
 * @param serviceInvocation  The service invocation object.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_service_invocation_free(NabtoDeviceServiceInvocation* serviceInvocation);

/**
 * Stop a service invocation.
 * If a coap request is in progress this request will be stopped.
 *
 * @param serviceInvocation  The service invocation object.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_service_invocation_stop(NabtoDeviceServiceInvocation* serviceInvocation);

/**
 * Set the service id to invoke. The service id is configured in the nabto cloud console.
 *
 * @param serviceInvocation  The service invocation object.
 * @param serviceId  The service id.
 * @return NABTO_DEVICE_EC_OK  iff the serviceId is set.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_service_invocation_set_service_id(NabtoDeviceServiceInvocation* serviceInvocation, const char* serviceId);

/**
 * Set the message for the service invocation. The message is handled as binary data.
 *
 * @param serviceInvocation  The service invocation object.
 * @param message  The message.
 * @param messageLength  Length of the message.
 * @return NABTO_DEVICE_EC_OK  iff the message is set.
 *         NABTO_DEVICE_EC_OUT_OF_MEMORY  if memory allocation failed.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_service_invocation_set_message(NabtoDeviceServiceInvocation* serviceInvocation, const uint8_t* message, size_t messageLength);

/**
 * Invoke a service. The future resolves with the status of the operation. After
 * the invocation has succeeded the response message and status code can be read
 * from the object.
 *
 * The future status is
 *  - NABTO_DEVICE_EC_OK if the invocation succeeded.
 *  - NABTO_DEVICE_EC_FAILED if the invocation failed, see the log for further
 *    error diagnosis.
 *
 * @param serviceInvocation  The service invocation object.
 * @param future  The future which is resolved when the result is ready.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_service_invocation_execute(NabtoDeviceServiceInvocation* serviceInvocation, NabtoDeviceFuture* future);

/**
 * Get the status code from the service invocation, the behavior is undefined if
 * the invocation failed or has not yet been invoked.
 *
 * @param serviceInvocation  The service invocation object.
 * @return  the statusCode
 */
NABTO_DEVICE_DECL_PREFIX uint16_t NABTO_DEVICE_API
nabto_device_service_invocation_get_response_status_code(NabtoDeviceServiceInvocation* serviceInvocation);

/**
 * Get the response message from the service invocation. The message is undefined
 * if the service invocation failed.
 *
 * @param serviceInvocation  The service invocation object.
 * @return  A pointer to the start of the response message. This pointer is alive until the service invocation object is freed.
 */
NABTO_DEVICE_DECL_PREFIX const uint8_t* NABTO_DEVICE_API
nabto_device_service_invocation_get_response_message_data(NabtoDeviceServiceInvocation* serviceInvocation);

/**
 * Get the length of the response message from the service invocation. Undefined if the invocation failed.
 *
 * @param serviceInvocation  The service invocation object.
 * @return  The length of the response message.
 */
NABTO_DEVICE_DECL_PREFIX size_t NABTO_DEVICE_API
nabto_device_service_invocation_get_response_message_size(NabtoDeviceServiceInvocation* serviceInvocation);


/********
 * Misc
 ********/

/**
 * @intro Misc
 *
 * Functions for getting the SDK version, accessing error info and
 * freeing SDK allocated resources.
 */

/**
 * Return the version of the Nabto embedded library. The returned pointer must not be freed.
 *
 * @return Zero-terminated string with the device version
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_version();

/**
 * Get message assosiated with an error code. The returned pointer must not be freed.
 *
 * @param error [in]  The error code.
 * @return Zero-terminated string describing the error.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_error_get_message(NabtoDeviceError error);

/**
 * Get the error code as a string. The returned pointer must not be freed.
 *
 * E.g. NABTO_DEVICE_EC_OK is translated to the string "NABTO_DEVICE_EC_OK"
 *
 * @param error [in]  The error code.
 * @return the NULL terminated string representation.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_error_get_string(NabtoDeviceError error);

/**
 * Free a string allocated by the device.
 *
 * @param str  The string to free
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_string_free(char* str);


#ifdef __cplusplus
} // extern c
#endif

#endif
