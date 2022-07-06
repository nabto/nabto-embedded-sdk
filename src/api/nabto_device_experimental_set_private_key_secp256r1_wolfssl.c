#include <nabto/nabto_device_experimental.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_API

#if defined(NABTO_USE_WOLFSSL)

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>

static uint8_t secp2566r1GroupOrder[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

// compare bytes from msb to lsb find the first difference it tells which number is biggest.
static bool compare_key_against_group_order(const uint8_t* key, size_t keyLength)
{
    if (keyLength != 32) {
        return false;
    }
    for (size_t i = 0; i < 32; i++) {
        uint8_t o = secp2566r1GroupOrder[i];
        uint8_t k = key[i];
        if (k > o) {
            return false;
        }
        if (k < o) {
            return true;
        }
        // else equal goto next byte.
    }
    // the key is exactly the group order, that is one too large.
    return false;
}


static NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_private_key_secp256r1_2(NabtoDevice* device, const uint8_t* key, size_t keyLength, ecc_key* eccKey);

NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_private_key_secp256r1(NabtoDevice* device, const uint8_t* key, size_t keyLength)
{
    if (!compare_key_against_group_order(key, keyLength)) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }

    ecc_key eccKey;
    int ret;
    ret = wc_ecc_init (&eccKey);
    if (ret < 0) {
        return NABTO_DEVICE_EC_FAILED;
    }
    NabtoDeviceError ec = nabto_device_set_private_key_secp256r1_2(device, key, keyLength, &eccKey);
    wc_ecc_free(&eccKey);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_private_key_secp256r1_2(NabtoDevice* device, const uint8_t* key, size_t keyLength, ecc_key* eccKey)
{
    int ret;
    ret = wc_ecc_import_private_key_ex(key, keyLength, NULL, 0, eccKey, ECC_SECP256R1);
    if (ret < 0) {
        NABTO_LOG_ERROR(LOG, "cannot import private key %i", ret);
        return NABTO_DEVICE_EC_FAILED;
    }

    ret = wc_ecc_make_pub(eccKey, NULL);
    if (ret < 0) {
        NABTO_LOG_ERROR(LOG, "cannot generate public key %i", ret);
        return NABTO_DEVICE_EC_FAILED;
    }


    uint8_t derBuffer[256];
    uint8_t pemBuffer[512];
    int derKeyLength = wc_EccKeyToDer(eccKey, derBuffer, sizeof(derBuffer));
    if (derKeyLength < 0) {
        NABTO_LOG_ERROR(LOG, "Cannot convert key to der %i", derKeyLength);
        return NABTO_DEVICE_EC_FAILED;
    }

    memset(pemBuffer, 0, sizeof(pemBuffer));
    int pemKeyLength = wc_DerToPem(derBuffer, derKeyLength, pemBuffer, sizeof(pemBuffer)-1, ECC_PRIVATEKEY_TYPE);
    if (pemKeyLength < 0) {
        NABTO_LOG_ERROR(LOG, "Cannot convert der key to pem %i", pemKeyLength);
        return NABTO_DEVICE_EC_FAILED;
    }

    return nabto_device_set_private_key(device, (const char*)pemBuffer);
}

#endif
