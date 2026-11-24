#include <nabto/nabto_device_config.h>
#include <nabto/nabto_device_experimental.h>
#include <platform/np_allocator.h>
#include <platform/np_logging.h>

#if defined(NABTO_DEVICE_OPENSSL)

#include <modules/openssl/nm_openssl_util.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>

#define LOG NABTO_LOG_MODULE_API

// Create an EVP_PKEY from the private scalar d. The public key d*G is
// calculated as it is part of the key.
static EVP_PKEY* create_key(const BIGNUM* d)
{
    EVP_PKEY* pkey = NULL;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT* pub = NULL;
    OSSL_PARAM_BLD* bld = NULL;
    OSSL_PARAM* params = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    uint8_t pubBuffer[65];

    if (group == NULL) {
        goto out;
    }
    pub = EC_POINT_new(group);
    if (pub == NULL || EC_POINT_mul(group, pub, d, NULL, NULL, NULL) != 1) {
        goto out;
    }
    size_t pubLength = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, pubBuffer, sizeof(pubBuffer), NULL);
    if (pubLength == 0) {
        goto out;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL ||
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, SN_X9_62_prime256v1, 0) != 1 ||
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pubBuffer, pubLength) != 1) {
        goto out;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (params == NULL || ctx == NULL ||
        EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

out:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EC_POINT_free(pub);
    EC_GROUP_free(group);
    return pkey;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_private_key_secp256r1(NabtoDevice* device, const uint8_t* key, size_t keyLength)
{
    if (keyLength != 32) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }

    BIGNUM* d = BN_secure_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (d == NULL || group == NULL || BN_bin2bn(key, (int)keyLength, d) == NULL) {
        BN_clear_free(d);
        EC_GROUP_free(group);
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }

    // Valid private keys are in [1, n-1]
    if (BN_is_zero(d) || BN_cmp(d, EC_GROUP_get0_order(group)) >= 0) {
        BN_clear_free(d);
        EC_GROUP_free(group);
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }
    EC_GROUP_free(group);
    BN_set_flags(d, BN_FLG_CONSTTIME);

    EVP_PKEY* pkey = create_key(d);
    BN_clear_free(d);
    if (pkey == NULL) {
        NABTO_LOG_ERROR(LOG, "Cannot create the private key");
        nm_openssl_util_log_errors(LOG);
        return NABTO_DEVICE_EC_FAILED;
    }

    char* pem = NULL;
    np_error_code ec = nm_openssl_util_private_key_to_pem(pkey, &pem);
    EVP_PKEY_free(pkey);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Cannot convert the private key to pem");
        return NABTO_DEVICE_EC_FAILED;
    }

    NabtoDeviceError status = nabto_device_set_private_key(device, pem);
    np_free(pem);
    return status;
}

#endif
