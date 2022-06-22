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

np_error_code nm_dtls_util_fp_from_crt(const WOLFSSL_X509* crt, uint8_t* hash)
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

// np_error_code nm_wolfssl_util_get_fp_from_cert(const char* cert, size_t certLen)
// {

//     wolfSSL_X509_d2i
// }

// struct crt_from_private_key {
//     wolfssl_pk_context key;
//     wolfssl_entropy_context entropy;
//     wolfssl_ctr_drbg_context ctr_drbg;

//     wolfssl_x509write_cert crt;
//     wolfssl_mpi serial;
// };

// static np_error_code nm_dtls_create_crt_from_private_key_inner(struct crt_from_private_key* ctx, const char* privateKey, char** publicKey);

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

// np_error_code nm_dtls_create_crt_from_private_key_inner(struct crt_from_private_key* ctx, const char* privateKey, char** publicKey)
// {
//     int ret;
//     ret = wolfssl_ctr_drbg_seed(&ctx->ctr_drbg, wolfssl_entropy_func, &ctx->entropy, NULL, 0);
//     if (ret != 0) {
//         return NABTO_EC_UNKNOWN;
//     }

//     ret = wolfssl_pk_parse_key( &ctx->key, (const unsigned char*)privateKey, strlen(privateKey)+1, NULL, 0 );
//     if (ret != 0) {
//         return NABTO_EC_UNKNOWN;
//     }

//     // initialize crt
//     wolfssl_x509write_crt_set_subject_key( &ctx->crt, &ctx->key );
//     wolfssl_x509write_crt_set_issuer_key( &ctx->crt, &ctx->key );

//     ret = wolfssl_mpi_read_string( &ctx->serial, 10, "1");
//     if (ret != 0) {
//         return NABTO_EC_UNKNOWN;
//     }

//     wolfssl_x509write_crt_set_serial( &ctx->crt, &ctx->serial );

//     ret = wolfssl_x509write_crt_set_subject_name( &ctx->crt, "CN=nabto" );
//     if (ret != 0) {
//         return NABTO_EC_UNKNOWN;
//     }

//     ret = wolfssl_x509write_crt_set_issuer_name( &ctx->crt, "CN=nabto" );
//     if (ret != 0) {
//         return NABTO_EC_UNKNOWN;
//     }

//     wolfssl_x509write_crt_set_version( &ctx->crt, 2 );
//     wolfssl_x509write_crt_set_md_alg( &ctx->crt, wolfssl_MD_SHA256 );

//     ret = wolfssl_x509write_crt_set_validity( &ctx->crt, "20010101000000", "20491231235959" );
//     if (ret != 0) {
//         return NABTO_EC_UNKNOWN;
//     }

//     ret = wolfssl_x509write_crt_set_basic_constraints( &ctx->crt, 1, -1);
//     if (ret != 0) {
//         return NABTO_EC_UNKNOWN;
//     }

//     {
//         // write crt
//         char buffer[1024];
//         memset(buffer, 0, 1024);
//         ret = wolfssl_x509write_crt_pem( &ctx->crt, (unsigned char*)buffer, 1024,
//                                          wolfssl_ctr_drbg_random, &ctx->ctr_drbg );

//         if (ret != 0) {
//             return NABTO_EC_UNKNOWN;
//         }
//         *publicKey = nn_strdup(buffer, np_allocator_get());
//     }
//     if (*publicKey == NULL) {
//         return NABTO_EC_UNKNOWN;
//     }
//     return NABTO_EC_OK;
// }


// np_error_code nm_dtls_get_fingerprint_from_private_key(const char* privateKey, uint8_t* hash)
// {
//     wolfssl_pk_context key;
//     int ret;

//     np_error_code ec = NABTO_EC_OK;
//     wolfssl_pk_init(&key);
//     ret = wolfssl_pk_parse_key( &key, (const unsigned char*)privateKey, strlen(privateKey)+1, NULL, 0 );
//     if (ret != 0) {
//         ec = NABTO_EC_UNKNOWN;
//     } else {
//         // get fingerprint
//         uint8_t buffer[256];
//         // !!! The key is written to the end of the buffer
//         int len = wolfssl_pk_write_pubkey_der( &key, buffer, sizeof(buffer));
//         if (len <= 0) {
//             ec = NABTO_EC_UNKNOWN;
//         } else {
//             ret = wolfssl_sha256_ret(buffer+256 - len,  len, hash, false);
//             if (ret != 0) {
//                 ec = NABTO_EC_UNKNOWN;
//             }
//         }
//     }
//     wolfssl_pk_free(&key);
//     return ec;
// }

np_error_code nm_wolfssl_util_create_private_key(char** privateKey)
{
    ecc_key key;
    int ret;
    // TODO deini key
    ret = wc_ecc_init(&key);
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }
    WC_RNG rng;
    // TODO deinit
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }
    ret = wc_ecc_make_key(&rng, 32, &key); // initialize 32 byte ecc key
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    uint8_t derBuffer[256];
    ret = wc_EccKeyToDer(&key, derBuffer, sizeof(derBuffer));
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
