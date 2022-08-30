#include <nabto/nabto_device_config.h>
#include "nm_wolfssl_util.h"

#include <platform/np_allocator.h>
#include <platform/np_logging.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_PLATFORM

np_error_code nm_wolfssl_util_fp_from_crt(const WOLFSSL_X509* crt,
                                          uint8_t* hash)
{
    uint8_t buffer[256];
    int requiredSize = sizeof(buffer);
    if (wolfSSL_X509_get_pubkey_buffer((WOLFSSL_X509*)crt, buffer,
                                       &requiredSize) != WOLFSSL_SUCCESS) {
        return NABTO_EC_FAILED;
    }

    np_error_code ec = NABTO_EC_OK;
    wc_Sha256 sha;
    if (wc_InitSha256(&sha) != 0) {
        return NABTO_EC_FAILED;
    }
    if (wc_InitSha256(&sha) == 0 &&
        wc_Sha256Update(&sha, buffer, requiredSize) == 0 &&
        wc_Sha256Final(&sha, hash) == 0)
    {

    } else {
        ec = NABTO_EC_FAILED;
    }
    wc_Sha256Free(&sha);
    return ec;
}

np_error_code nm_wolfssl_create_crt_from_private_key(const char* privateKey,
                                                     char** certOut)
{
    uint8_t derBuffer[256];

    int ret;

    Cert cert; // cert does not need an free function.
    ret = wc_InitCert(&cert);

    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    ecc_key eccKey;
    ret = wc_ecc_init(&eccKey);
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) {
        wc_ecc_free(&eccKey);
        return NABTO_EC_FAILED;
    }

    np_error_code ec = NABTO_EC_OK;

    ret = wc_KeyPemToDer((const unsigned char*)privateKey, strlen(privateKey),
                         derBuffer, sizeof(derBuffer), NULL);
    if (ret < 0) {
        ec = NABTO_EC_FAILED;
    }

    if (ec == NABTO_EC_OK) {
        word32 idx = 0;
        ret = wc_EccPrivateKeyDecode(derBuffer, &idx, &eccKey, ret);
        if (ret < 0) {
            ec = NABTO_EC_FAILED;
        }
    }

    uint8_t derCert[512];

    if (ec == NABTO_EC_OK) {
        // Create a selfsigned certificate, this can be moved somewhere else.
        // The end result is that the embedded dtls client uses a self signed
        // certificate.
        strncpy(cert.subject.commonName, "nabto", CTC_NAME_SIZE);
        strncpy(cert.issuer.commonName, "nabto", CTC_NAME_SIZE);

        cert.isCA = 0;
        cert.selfSigned = 1;
        cert.serial[0] = 0x01;
        cert.serialSz = 1;

        // Not before: 20 01 01 00 00 00 Z, 0x17 = UTC time, 0x0d = length, not after 2049 01 01 00 00 00 Z
        const uint8_t notBefore[] = { 0x17, 0x0d, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a };
        const uint8_t notAfter[] = { 0x17, 0xd, 0x34, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a };
        memcpy(cert.beforeDate, notBefore, sizeof(notBefore));
        cert.beforeDateSz = sizeof(notBefore);
        memcpy(cert.afterDate, notAfter, sizeof(notAfter));
        cert.afterDateSz = sizeof(notAfter);

        cert.sigType = CTC_SHA256wECDSA;

        ret = wc_MakeCert(&cert, derCert, sizeof(derCert), NULL, &eccKey, &rng);
        if (ret < 0) {
            ec = NABTO_EC_FAILED;
        }
    }

    int certLen;
    if (ec == NABTO_EC_OK) {
        certLen = wc_SignCert(cert.bodySz, cert.sigType, derCert,
                              sizeof(derCert), NULL, &eccKey, &rng);
        if (ret < 0) {
            ec = NABTO_EC_FAILED;
        }
    }

    uint8_t pemBuffer[512];

    if (ec == NABTO_EC_OK) {
        ret =
        wc_DerToPem(derCert, certLen, pemBuffer, sizeof(pemBuffer), CERT_TYPE);
        if (ret < 0) {
            return NABTO_EC_FAILED;
        }
    }

    if (ec == NABTO_EC_OK) {
        *certOut = np_calloc(1, ret + 1);
        if (*certOut == NULL) {
            ec = NABTO_EC_OUT_OF_MEMORY;
        } else {
            memcpy(*certOut, pemBuffer, ret);
        }
    }

    wc_FreeRng(&rng);
    wc_ecc_free(&eccKey);
    return ec;
}

np_error_code nm_wolfssl_get_fingerprint_from_private_key(
    const char* privateKey, uint8_t* hash)
{
    uint8_t publicKeyDer[256];
    int publicKeyDerSize;

    np_error_code ec = NABTO_EC_OK;

    int ret;
    {
        uint8_t derBuffer[256];
        ecc_key eccKey;
        ret = wc_ecc_init(&eccKey);
        if (ret != 0) {
            return NABTO_EC_FAILED;
        }

        ret =
            wc_KeyPemToDer((const unsigned char*)privateKey, strlen(privateKey),
                           derBuffer, sizeof(derBuffer), NULL);
        if (ret < 0) {
            ec = NABTO_EC_FAILED;
        }

        if (ec == NABTO_EC_OK) {
            word32 idx = 0;
            ret = wc_EccPrivateKeyDecode(derBuffer, &idx, &eccKey, ret);
            if (ret < 0) {
                ec = NABTO_EC_FAILED;
            }
        }

        //uint8_t publicKeyDer[256];
        if (ec == NABTO_EC_OK) {
            publicKeyDerSize = wc_EccPublicKeyToDer(&eccKey, publicKeyDer,
                                       sizeof(publicKeyDer), 1);
            if (publicKeyDerSize < 0) {
                ec = NABTO_EC_FAILED;
            }
        }

        wc_ecc_free(&eccKey);
    }

    if (ec == NABTO_EC_OK) {
        wc_Sha256 sha;
        ret = wc_InitSha256(&sha);
        if (ret != 0) {
            return NABTO_EC_FAILED;
        }

        ret = wc_Sha256Update(&sha, publicKeyDer, publicKeyDerSize);
        if (ret != 0) {
            ec = NABTO_EC_FAILED;
        }
        ret = wc_Sha256Final(&sha, hash);
        if (ret != 0) {
            ec = NABTO_EC_FAILED;
        }
        wc_Sha256Free(&sha);
    }
    return ec;
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
        wc_ecc_free(&key);
        return NABTO_EC_FAILED;
    }

    np_error_code ec = NABTO_EC_OK;
    ret = wc_ecc_make_key(&rng, 32, &key);  // initialize 32 byte ecc key
    if (ret != 0) {
        ec = NABTO_EC_FAILED;
    }

    uint8_t derBuffer[256];
    if (ec == NABTO_EC_OK) {
        ret = wc_EccKeyToDer(&key, derBuffer, sizeof(derBuffer));
        if (ret < 0) {
            NABTO_LOG_ERROR(LOG, "Could not convert ecc key to der");
            ec = NABTO_EC_FAILED;
        }
    }

    uint8_t pemBuffer[256];

    if (ec == NABTO_EC_OK) {
        ret = wc_DerToPem(derBuffer, ret, pemBuffer, sizeof(pemBuffer),
                          ECC_PRIVATEKEY_TYPE);
        if (ret < 0) {
            NABTO_LOG_ERROR(LOG, "Cannot convert der to pem");
            ec = NABTO_EC_FAILED;
        }
    }

    if (ec == NABTO_EC_OK) {
        char* str = np_calloc(1, ret + 1);
        if (str == NULL) {
            ec = NABTO_EC_OUT_OF_MEMORY;
        } else {
            memcpy(str, pemBuffer, ret);
            *privateKey = str;
        }
    }

    wc_FreeRng(&rng);
    wc_ecc_free(&key);
    return ec;
}

#if defined(NABTO_DEVICE_DTLS_LOG)
static void logging_callback(const int logLevel, const char *const logMessage)
{
    uint32_t severity;
    switch (logLevel) {
        case 0:
            severity = NABTO_LOG_SEVERITY_ERROR;
            break;
        case 1:
            severity = NABTO_LOG_SEVERITY_INFO;
            break;
        default:
            severity = NABTO_LOG_SEVERITY_TRACE;
            break;
    }
    NABTO_LOG_RAW(severity, LOG, 0, "wolfssl", logMessage)
}
#endif

void nm_wolfssl_util_check_logging()
{
#if defined(NABTO_DEVICE_DTLS_LOG)
    wolfSSL_SetLoggingCb(logging_callback);
    wolfSSL_Debugging_ON();
    #else
    NABTO_LOG_ERROR(LOG, "NO DTLS LOG DEFINED");
#endif
}
