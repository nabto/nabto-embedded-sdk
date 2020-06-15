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

#ifdef __cplusplus
} // extern c
#endif

#endif
