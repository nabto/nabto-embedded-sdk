#include <nabto/nabto_device_experimental.h>
#include "nabto_device_defines.h"

#include <stdlib.h>

#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>


NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_private_key_secp256r1(NabtoDevice* device, const uint8_t* key, size_t keyLength)
{
    if (keyLength != 32) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }

    int status;
    const mbedtls_pk_info_t * pkInfo = mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY );


    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);

    status =  mbedtls_pk_setup( &pk, pkInfo);
    if (status != 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }


    mbedtls_ecp_keypair* keyPair = mbedtls_pk_ec(pk);
    if (keyPair == NULL) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }

    status = mbedtls_ecp_group_load( &keyPair->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (status != 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }

    mbedtls_mpi_read_binary(&keyPair->d, key, keyLength);

    // Q = dG

    {
        status = mbedtls_ecp_mul(&keyPair->grp, &keyPair->Q, &keyPair->d, &keyPair->grp.G, NULL, NULL);
        if (status != 0) {
            return NABTO_DEVICE_EC_INVALID_STATE;
        }
    }

    // keyPair is an ecc keyPair, just write it to pem.

    uint8_t buffer[2048];

    status = mbedtls_pk_write_key_pem(&pk, buffer, 2048);
    if (status != 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    mbedtls_pk_free(&pk);

    return nabto_device_set_private_key(device, (const char*)buffer);
}
