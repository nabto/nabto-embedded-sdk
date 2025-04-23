#ifndef NABTO_DEVICE_EXPERIMENTAL_H_
#define NABTO_DEVICE_EXPERIMENTAL_H_

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
 * @param device [in]  the device
 * @param key [in]  The key as 32 bytes data.
 * @param keyLength [in]  Must be 32.
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

#ifdef __cplusplus
} // extern c #endif
#endif

#endif
