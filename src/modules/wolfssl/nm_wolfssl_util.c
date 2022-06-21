#include "nm_wolfssl_util.h"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha.h>
// #include "wolfssl/error.h"
// #include "wolfssl/pk.h"
// #include "wolfssl/ecdsa.h"
// #include "wolfssl/rsa.h"
// #include "wolfssl/error.h"
// #include "wolfssl/entropy.h"
// #include "wolfssl/ctr_drbg.h"
// #include "wolfssl/platform.h"
// #include "wolfssl/x509_crt.h"
// #include "wolfssl/x509_csr.h"
// #include "wolfssl/sha256.h"

#include <platform/np_allocator.h>

#include <nn/string.h>
#include <string.h>

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

// struct crt_from_private_key {
//     wolfssl_pk_context key;
//     wolfssl_entropy_context entropy;
//     wolfssl_ctr_drbg_context ctr_drbg;

//     wolfssl_x509write_cert crt;
//     wolfssl_mpi serial;
// };

// static np_error_code nm_dtls_create_crt_from_private_key_inner(struct crt_from_private_key* ctx, const char* privateKey, char** publicKey);

// np_error_code nm_dtls_create_crt_from_private_key(const char* privateKey, char** publicKey)
// {
//     // 1. load key from pem
//     // 2. create crt
//     // 3. write to pem string.
//     struct crt_from_private_key ctx;

//     *publicKey = NULL;

//     wolfssl_pk_init(&ctx.key);
//     wolfssl_ctr_drbg_init(&ctx.ctr_drbg);
//     wolfssl_entropy_init(&ctx.entropy);
//     wolfssl_x509write_crt_init(&ctx.crt);
//     wolfssl_mpi_init(&ctx.serial);

//     np_error_code ec = nm_dtls_create_crt_from_private_key_inner(&ctx, privateKey, publicKey);

//     wolfssl_x509write_crt_free(&ctx.crt);
//     wolfssl_mpi_free(&ctx.serial);
//     wolfssl_ctr_drbg_free(&ctx.ctr_drbg);
//     wolfssl_entropy_free(&ctx.entropy);
//     wolfssl_pk_free(&ctx.key);

//     return ec;
// }

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

// np_error_code nm_dtls_util_create_private_key(char** privateKey)
// {
//     *privateKey = NULL;
//     unsigned char output_buf[1024];
//     wolfssl_pk_context key;
//     wolfssl_entropy_context entropy;
//     wolfssl_ctr_drbg_context ctr_drbg;
//     const char *pers = "gen_key";
//     np_error_code ec = NABTO_EC_OK;

//     memset(output_buf, 0, 1024);
//     wolfssl_pk_init( &key );
//     wolfssl_ctr_drbg_init( &ctr_drbg );

//     wolfssl_entropy_init( &entropy );

//     if( (wolfssl_ctr_drbg_seed( &ctr_drbg, wolfssl_entropy_func, &entropy,
//                                 (const unsigned char *) pers,
//                                 strlen( pers ) ) != 0) ||
//         (wolfssl_pk_setup( &key, wolfssl_pk_info_from_type( wolfssl_PK_ECKEY ) ) != 0 ) ||
//         (wolfssl_ecp_gen_key( wolfssl_ECP_DP_SECP256R1,
//                               wolfssl_pk_ec( key ),
//                               wolfssl_ctr_drbg_random, &ctr_drbg ) != 0) ||
//         (wolfssl_pk_write_key_pem( &key, output_buf, 1024 ) != 0 ))
//     {
//         ec = NABTO_EC_UNKNOWN;
//     } else {
//         *privateKey = nn_strdup((char*)output_buf, np_allocator_get());
//     }

//     wolfssl_pk_free( &key );
//     wolfssl_ctr_drbg_free( &ctr_drbg );
//     wolfssl_entropy_free( &entropy );

//     return ec;
// }
