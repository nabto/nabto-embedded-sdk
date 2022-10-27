#include <nabto/nabto_device_config.h>
#include "nm_mbedtls_util.h"
#include <mbedtls/sha256.h>
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/sha256.h"
#include <mbedtls/debug.h>

#include <platform/np_allocator.h>
#include <platform/np_logging.h>

#include <nn/string.h>
#include <string.h>

#define LOG NABTO_LOG_MODULE_PLATFORM

np_error_code nm_mbedtls_util_fp_from_crt(const mbedtls_x509_crt* crt, uint8_t* hash)
{
    uint8_t buffer[256];

    mbedtls_pk_context *ctx = (mbedtls_pk_context*)(&crt->pk);
    int len = mbedtls_pk_write_pubkey_der( ctx, buffer, sizeof(buffer));
    if (len <= 0) {
        return NABTO_EC_UNKNOWN;
    }
    nm_mbedtls_sha256(buffer+sizeof(buffer)-len, len, hash);
    return NABTO_EC_OK;
}

struct crt_from_private_key {
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
};

static np_error_code nm_dtls_create_crt_from_private_key_inner(struct crt_from_private_key* ctx, const char* privateKey, char** publicKey);

np_error_code nm_mbedtls_create_crt_from_private_key(const char* privateKey, char** publicKey)
{
    // 1. load key from pem
    // 2. create crt
    // 3. write to pem string.
    struct crt_from_private_key ctx;

    *publicKey = NULL;

    mbedtls_pk_init(&ctx.key);
    mbedtls_ctr_drbg_init(&ctx.ctr_drbg);
    mbedtls_entropy_init(&ctx.entropy);
    mbedtls_x509write_crt_init(&ctx.crt);
    mbedtls_mpi_init(&ctx.serial);

    np_error_code ec = nm_dtls_create_crt_from_private_key_inner(&ctx, privateKey, publicKey);

    mbedtls_x509write_crt_free(&ctx.crt);
    mbedtls_mpi_free(&ctx.serial);
    mbedtls_ctr_drbg_free(&ctx.ctr_drbg);
    mbedtls_entropy_free(&ctx.entropy);
    mbedtls_pk_free(&ctx.key);

    return ec;
}

np_error_code nm_dtls_create_crt_from_private_key_inner(struct crt_from_private_key* ctx, const char* privateKey, char** publicKey)
{
    int ret;
    ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, NULL, 0);
    if (ret != 0) {
        return NABTO_EC_UNKNOWN;
    }

    const unsigned char* p =  (const unsigned char*)privateKey;
    size_t pLen = strlen(privateKey) + 1;
#if MBEDTLS_VERSION_MAJOR >= 3
    ret = mbedtls_pk_parse_key( &ctx->key, p, pLen, NULL, 0, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
#else
    ret = mbedtls_pk_parse_key( &ctx->key, p, pLen, NULL, 0);
#endif
    if (ret != 0) {
        return NABTO_EC_UNKNOWN;
    }

    // initialize crt
    mbedtls_x509write_crt_set_subject_key( &ctx->crt, &ctx->key );
    mbedtls_x509write_crt_set_issuer_key( &ctx->crt, &ctx->key );

    ret = mbedtls_mpi_read_string( &ctx->serial, 10, "1");
    if (ret != 0) {
        return NABTO_EC_UNKNOWN;
    }

    mbedtls_x509write_crt_set_serial( &ctx->crt, &ctx->serial );

    ret = mbedtls_x509write_crt_set_subject_name( &ctx->crt, "CN=nabto" );
    if (ret != 0) {
        return NABTO_EC_UNKNOWN;
    }

    ret = mbedtls_x509write_crt_set_issuer_name( &ctx->crt, "CN=nabto" );
    if (ret != 0) {
        return NABTO_EC_UNKNOWN;
    }

    mbedtls_x509write_crt_set_version( &ctx->crt, 2 );
    mbedtls_x509write_crt_set_md_alg( &ctx->crt, MBEDTLS_MD_SHA256 );

    ret = mbedtls_x509write_crt_set_validity( &ctx->crt, "20010101000000", "20491231235959" );
    if (ret != 0) {
        return NABTO_EC_UNKNOWN;
    }

    ret = mbedtls_x509write_crt_set_basic_constraints( &ctx->crt, 1, -1);
    if (ret != 0) {
        return NABTO_EC_UNKNOWN;
    }

    {
        // write crt
        size_t bufferSize = 1024;
        char* buffer = np_calloc(1,1024);
        if (buffer == NULL) {
            return NABTO_EC_OUT_OF_MEMORY;
        }
        ret = mbedtls_x509write_crt_pem( &ctx->crt, (unsigned char*)buffer, bufferSize,
                                         mbedtls_ctr_drbg_random, &ctx->ctr_drbg );

        if (ret != 0) {
            np_free(buffer);
            return NABTO_EC_UNKNOWN;
        }
        *publicKey = nn_strdup(buffer, np_allocator_get());
        np_free(buffer);
    }
    if (*publicKey == NULL) {
        return NABTO_EC_UNKNOWN;
    }
    return NABTO_EC_OK;
}


np_error_code nm_mbedtls_get_fingerprint_from_private_key(const char* privateKey, uint8_t* hash)
{
    mbedtls_pk_context key;
    int ret;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_pk_init(&key);

    np_error_code ec = NABTO_EC_OK;

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        ec = NABTO_EC_UNKNOWN;
    } else {
        const unsigned char* p = (const unsigned char*)privateKey;
        size_t pLen = strlen(privateKey)+1;
#if MBEDTLS_VERSION_MAJOR >= 3
        ret = mbedtls_pk_parse_key( &key, p, pLen, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
#else
        ret = mbedtls_pk_parse_key( &key, p, pLen, NULL, 0);
#endif
    }

    if (ret != 0) {
        ec = NABTO_EC_UNKNOWN;
    } else {
        // get fingerprint
        uint8_t buffer[256];
        // !!! The key is written to the end of the buffer
        int len = mbedtls_pk_write_pubkey_der( &key, buffer, sizeof(buffer));
        if (len <= 0) {
            ec = NABTO_EC_UNKNOWN;
        } else {
            ret = nm_mbedtls_sha256(buffer+256 - len,  len, hash);
            if (ret != 0) {
                ec = NABTO_EC_UNKNOWN;
            }
        }
    }

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    mbedtls_pk_free(&key);
    return ec;
}

np_error_code nm_mbedtls_util_create_private_key(char** privateKey)
{
    *privateKey = NULL;
    size_t outputBufferSize = 1024;
    unsigned char* outputBuffer = np_calloc(1, outputBufferSize);
    if (outputBuffer == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";
    np_error_code ec = NABTO_EC_OK;

    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_init( &entropy );

    if( (mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *) pers,
                                strlen( pers ) ) != 0) ||
        (mbedtls_pk_setup( &key, mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) ) != 0 ) ||
        (mbedtls_ecp_gen_key( MBEDTLS_ECP_DP_SECP256R1,
                              mbedtls_pk_ec( key ),
                              mbedtls_ctr_drbg_random, &ctr_drbg ) != 0) ||
        (mbedtls_pk_write_key_pem( &key, outputBuffer, outputBufferSize ) != 0 ))
    {
        ec = NABTO_EC_UNKNOWN;
    } else {
        *privateKey = nn_strdup((char*)outputBuffer, np_allocator_get());
    }
    np_free(outputBuffer);

    mbedtls_pk_free( &key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return ec;
}

#if defined(NABTO_DEVICE_DTLS_LOG)
static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level); (void)ctx;
    uint32_t severity;
    switch (level) {
        case 1:
            severity = NABTO_LOG_SEVERITY_ERROR;
            break;
        case 2:
            severity = NABTO_LOG_SEVERITY_INFO;
            break;
        default:
            severity = NABTO_LOG_SEVERITY_TRACE;
            break;
    }

    NABTO_LOG_RAW(severity, LOG, line, file, str );
}
#endif

void nm_mbedtls_util_check_logging(mbedtls_ssl_config* conf)
{
#if defined(NABTO_DEVICE_DTLS_LOG)
    mbedtls_debug_set_threshold( 4 ); // Max debug threshold, NABTO_LOG_RAW will handle log levels
    mbedtls_ssl_conf_dbg( conf, my_debug, NULL);
#endif
}

int nm_mbedtls_sha256( const unsigned char *input, size_t ilen, unsigned char output[32] )
{
#if MBEDTLS_VERSION_MAJOR >= 3
    return mbedtls_sha256(input, ilen, output, 0);
#else
    return mbedtls_sha256_ret(input, ilen, output, 0);
#endif
}


int nm_mbedtls_recv_data(mbedtls_ssl_context *ssl, uint8_t** data)
{
    int ret;
    uint8_t smallRecvBuffer[16];
    size_t smallRecvBufferSize = sizeof(smallRecvBuffer);
    // first recv 1 byte and then retrieve the rest or discard the data if a packet large enough cannot be allocated.
    ret = mbedtls_ssl_read( ssl, smallRecvBuffer, smallRecvBufferSize );
    if (ret <= 0) {
        return ret;
    }

    // we have received the first part of the data receive the last part of the
    // data.
    size_t smallRecvLength = ret;
    size_t remaining = mbedtls_ssl_get_bytes_avail(ssl);
    size_t totalRecvLength = smallRecvLength;

    uint8_t* recvBuffer = np_calloc(1, smallRecvLength + remaining);
    if (recvBuffer == NULL) {
        // discard the data
        while (ret > 0) {
            ret = mbedtls_ssl_read(ssl, smallRecvBuffer, smallRecvBufferSize);
        }
        return ret;
    }

    memcpy(recvBuffer, smallRecvBuffer, smallRecvLength);
    if (remaining > 0) {
        ret = mbedtls_ssl_read(ssl, recvBuffer + smallRecvLength, remaining);
        if (ret <= 0) {
            np_free(recvBuffer);
            return ret;
        }
        totalRecvLength += ret;
    }
    *data = recvBuffer;
    return totalRecvLength;
}
