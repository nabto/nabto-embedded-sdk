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
 * Disable remote access. When disabled, the device will not attempt
 * to connect to the Nabto Basestation and clients will only be able
 * to connect to the device directly (local connection using mdns
 * discovery or with direct candidates). This function must be called
 * before nabto_device_start();
 *
 * @param device [in]  The device.
 * @return NABTO_DEVICE_EC_OK on success
 *         NABTO_DEVICE_INVALID_STATE if device is started
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_disable_remote_access(NabtoDevice* device);


/**
 * Firebase Cloud Messaging(FCM) notifications.
 *
 * This functionality makes it possible to send FCM notifications through the
 * connection which exists between the device and the basestation.
 * 
 * See .... for further explanation
 */

/**
 * FCM Notification. This is an object holding the FCM notification request and
 * after the basestation api has been invoked the response from the invocation
 * also exists in the object.
 */
typedef struct NabtoDeviceFcmNotification_ NabtoDeviceFcmNotification;

/**
 * Create a new FCM Notification
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceFcmNotification* NABTO_DEVICE_API 
nabto_device_fcm_notification_new(NabtoDevice* device);

/**
 * Free a FCM notification
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API 
nabto_device_fcm_notification_free(NabtoDeviceFcmNotification* notification);

/**
 * Set the FCM project id on a notification
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API 
nabto_device_fcm_notification_set_project_id(NabtoDeviceFcmNotification* notification, const char* projectId);

/**
 * Set a JSON document/payload according to the format
 * https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages/send
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API 
nabto_device_fcm_notification_set_payload(NabtoDeviceFcmNotification* notification, const char* payload);

/**
 * Send a notification.
 *
 * The future returns NABTO_DEVICE_EC_OK iff the invocation of the basestation
 * went ok. If the invocation went ok the firebase response can be found using
 * nabto_device_fcm_notification_get_response_status_code and
 * nabto_device_fcm_notification_get_response_body. The response status code is
 * generally enough to determine if a message went ok or not. The response body
 * can be used to get a detailed description in the case an error occurs.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_fcm_send(NabtoDeviceFcmNotification* notification, NabtoDeviceFuture* future);

/**
 * Get the response status code from the FCM invocation in case the send went ok.
 * 
 * 200, If the notification was sent ok.
 * 400, If the notification has an invalid format.
 * 403, If the notification could bot be sent due to missing authorization.
 * 404, If the token is expired.
 * 
 * See https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode for detailed description of the errors.
 */
NABTO_DEVICE_DECL_PREFIX uint16_t NABTO_DEVICE_API
nabto_device_fcm_notification_get_response_status_code(NabtoDeviceFcmNotification* notification);

/**
 * Get the response body of the request to fcm. If an error occured this will
 * contain the description. If the send went ok the body will contain a name
 * which is the id of the sent message.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_fcm_notification_get_response_body(NabtoDeviceFcmNotification* notification);

/**
 * FCM Last will and testament. This allows registration of some notifications
 * which will be fulfilled by the basestation in the case where a device goes
 * unexpected offline. An example of such notification is "Your alarm system has
 * lost the internet connection". The concept LWT comes from MQTT and is not a
 * feature which is built into firebase, but a feature Nabto provides.
 *
 * This feature is implemented such that when nabto_device_fcm_lwt_add is called
 * the basestation invokes the firebase api with  "validate_only": true, this
 * validates the message structure and registration tokens. When a device later
 * goes offline in some unintended way, the LWT notifications which is stored in
 * the basestation is sent.
 */

/**
 * Reset the list of Lwts in the basestation
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API 
nabto_device_fcm_lwt_reset(NabtoDevice* device, NabtoDeviceFuture* future);

/**
 * Add a LWT notification.
 *
 * Nearly same semantics as nabto_device_fcm_send except that the message is
 * saved in the basestation such that it can be sent at a later time.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API 
nabto_device_fcm_lwt_add(NabtoDeviceFcmNotification* notification, NabtoDeviceFuture* future);


#ifdef __cplusplus
} // extern c
#endif

#endif
