#include <nabto/nabto_device_config.h>
#include <nabto/nabto_device_experimental.h>
#include <platform/np_logging.h>

#if defined(NABTO_DEVICE_MBEDTLS)


#define LOG NABTO_LOG_MODULE_API

// secp256r1 group order in bigendian.
static uint8_t secp2566r1GroupOrder[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

#if !defined(DEVICE_MBEDTLS_2)
#include <mbedtls/build_info.h>
#endif
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(m) m
#endif

NabtoDeviceError nabto_device_set_private_key_secp256r1_alloc(
    NabtoDevice* device, const uint8_t* key, size_t keyLength);

NabtoDeviceError nabto_device_set_private_key_secp256r1_compute(
    NabtoDevice* device, const uint8_t* key, size_t keyLength,
    mbedtls_pk_context* pk, mbedtls_mpi* n, mbedtls_entropy_context* entropy,
    mbedtls_ctr_drbg_context* ctrDrbg);

NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_private_key_secp256r1(NabtoDevice* device, const uint8_t* key, size_t keyLength)
{
    return nabto_device_set_private_key_secp256r1_alloc(device, key, keyLength);
}

NabtoDeviceError nabto_device_set_private_key_secp256r1_alloc(NabtoDevice* device, const uint8_t* key, size_t keyLength)
{
    mbedtls_pk_context pk;
    mbedtls_mpi n; // n is the order of the secp256r1 group
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctrDrbg;

    mbedtls_pk_init(&pk);
    mbedtls_mpi_init(&n);
    mbedtls_ctr_drbg_init( &ctrDrbg );
    mbedtls_entropy_init( &entropy );

    NabtoDeviceError status = nabto_device_set_private_key_secp256r1_compute(
        device, key, keyLength, &pk, &n, &entropy, &ctrDrbg);

    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);

    mbedtls_pk_free(&pk);
    mbedtls_mpi_free(&n);

    return status;
}

NabtoDeviceError nabto_device_set_private_key_secp256r1_compute(
    NabtoDevice* device, const uint8_t* key, size_t keyLength,
    mbedtls_pk_context* pk, mbedtls_mpi* n, mbedtls_entropy_context* entropy,
    mbedtls_ctr_drbg_context* ctrDrbg)
{
    if (keyLength != 32) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }

    int status = 0;
    const mbedtls_pk_info_t * pkInfo = mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY );

    status =  mbedtls_pk_setup( pk, pkInfo);
    if (status != 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }

    status = mbedtls_ctr_drbg_seed( ctrDrbg, mbedtls_entropy_func, entropy, NULL, 0);
    if (status != 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }

    mbedtls_ecp_keypair* keyPair = mbedtls_pk_ec(*pk);
    if (keyPair == NULL) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }

    status = mbedtls_ecp_group_load( &keyPair->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
    if (status != 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }

    mbedtls_mpi_read_binary(&keyPair->MBEDTLS_PRIVATE(d), key, keyLength);

    mbedtls_mpi_read_binary(n, secp2566r1GroupOrder, 32);

    // valid private keys should be in the range [1,n-1], d != 0 && d < n;

    // test that d is not 0
    if (mbedtls_mpi_cmp_int(&keyPair->MBEDTLS_PRIVATE(d), 0) == 0) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }
    // test that d < n
    // check that d lesser than n, in this case the cmp function returns -1
    if (mbedtls_mpi_cmp_mpi(&keyPair->MBEDTLS_PRIVATE(d), n) != -1) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }

    // Q = dG

    {
        status = mbedtls_ecp_mul(&keyPair->MBEDTLS_PRIVATE(grp), &keyPair->MBEDTLS_PRIVATE(Q), &keyPair->MBEDTLS_PRIVATE(d), &keyPair->MBEDTLS_PRIVATE(grp).G, mbedtls_ctr_drbg_random, ctrDrbg);
        if (status != 0) {
            return NABTO_DEVICE_EC_INVALID_STATE;
        }
    }

    // keyPair is an ecc keyPair, write it to pem.

    // a pem encoded p256r1 key uses ~280 bytes including header and footer.
    // -----BEGIN EC PRIVATE KEY-----
    // base64 encoded asn1
    // -----END EC PRIVATE KEY-----
    uint8_t buffer[512];

    status = mbedtls_pk_write_key_pem(pk, buffer, sizeof(buffer));
    if (status != 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }

    return nabto_device_set_private_key(device, (const char*)buffer);
}

#endif
