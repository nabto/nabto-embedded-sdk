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
 * Opaque fcm notification.
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
 * Set a project id on a notification
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
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_fcm_send(NabtoDeviceFcmNotification* notification, NabtoDeviceFuture* future);

/**
 * FCM Last will and testament. This allows registration of some notifications
 * which will be fulfilled by the basestation in the case where a device goes
 * unexpected offline. This will be notifications like "Your alarm system has
 * lost the internet connection".
 * 
 * Usage:
 * nabto_device_fcm_lwt_reset(device);
 * foreach lwt notification in the system:
 *   nabto_device_fcm_lwt_add(device, notification);
 * nabto_device_fcm_lwt_sync(device);
 */

/**
 * reset the internal list of lwts.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API 
nabto_device_fcm_lwt_reset(NabtoDevice* device);

/**
 * Add a notification to LWT. The notification is copied to the system. 
 *
 * @return NABTO_DEVICE_EC_OK iff added.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API 
nabto_device_fcm_lwt_add(NabtoDevice* device, NabtoDeviceFcmNotification* notification);

/**
 * Synchronize the current list of lwts with the basestation. If the device is
 * attached a sync is scheduled. If the device is not attached lwts will be
 * synchronized the next time the device goes online.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API 
nabto_device_fcm_lwt_sync(NabtoDevice* device);


#ifdef __cplusplus
} // extern c
#endif

#endif
