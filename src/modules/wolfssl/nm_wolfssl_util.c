#include "nm_wolfssl_util.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <platform/np_allocator.h>
#include <platform/np_logging.h>

#include <nn/string.h>
#include <string.h>

#define LOG NABTO_LOG_MODULE_PLATFORM

np_error_code nm_wolfssl_util_fp_from_crt(const WOLFSSL_X509* crt, uint8_t* hash)
{
    int requiredSize = 0;
    if (wolfSSL_X509_get_pubkey_buffer((WOLFSSL_X509*)crt, NULL, &requiredSize) != WOLFSSL_SUCCESS) {
        return NABTO_EC_FAILED;
    }

    uint8_t* buffer = (uint8_t*)np_calloc(requiredSize, 1);
    if (buffer == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    if (wolfSSL_X509_get_pubkey_buffer((WOLFSSL_X509*)crt, buffer, &requiredSize) != WOLFSSL_SUCCESS) {
        np_free(buffer);
        return NABTO_EC_FAILED;
    }

    Sha256 sha;
    wc_InitSha256(&sha);

    wc_Sha256Update(&sha, buffer, requiredSize);
    wc_Sha256Final(&sha, hash);

    np_free(buffer);

    return NABTO_EC_OK;
}

np_error_code nm_wolfssl_create_crt_from_private_key(const char* privateKey, char** certOut)
{
    uint8_t derBuffer[256];

    int ret;
    ret = wc_KeyPemToDer((const unsigned char*)privateKey, strlen(privateKey), derBuffer, sizeof(derBuffer), NULL);
    if (ret < 0) {
        return NABTO_EC_FAILED;
    }

    ecc_key eccKey;
    word32 idx = 0;
    ret = wc_EccPrivateKeyDecode(derBuffer, &idx, &eccKey, ret);
    if (ret < 0) {
        return NABTO_EC_FAILED;
    }


    // Create a selfsigned certificate, this can be moved somewhere else. The
    // end result is that the embedded dtls client uses a self signed certificate.
    uint8_t derCert[512];

    Cert cert;
    wc_InitCert(&cert);

    strncpy(cert.subject.commonName, "nabto", CTC_NAME_SIZE);
    strncpy(cert.issuer.commonName, "nabto", CTC_NAME_SIZE);

    cert.isCA = 0;
    cert.selfSigned = 1;
    cert.serial[0] = 0x01;
    cert.serialSz = 1;
    // we create new certs for each startup
    cert.daysValid = 5000;

    WC_RNG rng;
    if (wc_InitRng(&rng) != 0)
    {
        return NABTO_EC_FAILED;
    }

    ret = wc_MakeCert(&cert, derCert, sizeof(derCert), NULL, &eccKey, &rng);
    if (ret < 0)
    {
        return NABTO_EC_FAILED;
    }

    int certLen = wc_SignCert(cert.bodySz, cert.sigType,
                              derCert, sizeof(derCert), NULL, &eccKey, &rng);
    if (ret < 0) {
        return NABTO_EC_FAILED;
    }

    uint8_t pemBuffer[512];

    ret = wc_DerToPem(derCert, certLen, pemBuffer, sizeof(pemBuffer), CERT_TYPE);
    if (ret < 0) {
        return NABTO_EC_FAILED;
    }

    *certOut = np_calloc(1, ret+1);
    if (*certOut == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    memcpy(*certOut, pemBuffer, ret);
    return NABTO_EC_OK;

}

np_error_code nm_wolfssl_get_fingerprint_from_private_key(const char* privateKey, uint8_t* hash)
{
    uint8_t derBuffer[256];

    int ret;
    ret = wc_KeyPemToDer((const unsigned char*)privateKey, strlen(privateKey), derBuffer, sizeof(derBuffer), NULL);
    if (ret < 0) {
        return NABTO_EC_FAILED;
    }

    ecc_key eccKey;
    word32 idx = 0;
    ret = wc_EccPrivateKeyDecode(derBuffer, &idx, &eccKey, ret);
    if (ret < 0) {
        return NABTO_EC_FAILED;
    }

    uint8_t publicKeyDer[256];

    ret = wc_EccPublicKeyToDer(&eccKey, publicKeyDer, sizeof(publicKeyDer), 0);
    if (ret < 0) {
        return NABTO_EC_FAILED;
    }


    Sha256 sha;
    wc_InitSha256(&sha);

    wc_Sha256Update(&sha, publicKeyDer, ret);
    wc_Sha256Final(&sha, hash);

    return NABTO_EC_OK;
    // TODO free resources
}

np_error_code nm_wolfssl_util_create_private_key_inner(char** privateKey, ecc_key* key, WC_RNG* rng)
{
    int ret;
    ret = wc_ecc_make_key(rng, 32, key); // initialize 32 byte ecc key
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    uint8_t derBuffer[256];
    ret = wc_EccKeyToDer(key, derBuffer, sizeof(derBuffer));
    if (ret < 0) {
        NABTO_LOG_ERROR(LOG, "Could not convert ecc key to der");
        return NABTO_EC_FAILED;
    }

    uint8_t pemBuffer[256];

    ret = wc_DerToPem(derBuffer, ret, pemBuffer, sizeof(pemBuffer), ECC_PRIVATEKEY_TYPE);
    if (ret < 0) {
        NABTO_LOG_ERROR(LOG, "Cannot convert der to pem");
        return NABTO_EC_FAILED;
    }

    char* str = np_calloc(1, ret+1);
    if (str == NULL)
    {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    memcpy(str, pemBuffer, ret);
    *privateKey = str;

    return NABTO_EC_OK;
}


np_error_code nm_wolfssl_util_create_private_key(char** privateKey)
{
    ecc_key key;
    int ret;
    ret = wc_ecc_init(&key);
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }
    WC_RNG rng;
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    np_error_code ec = nm_wolfssl_util_create_private_key_inner(privateKey, &key, &rng);

    wc_FreeRng(&rng);
    wc_ecc_free(&key);
    return ec;
}
