#include "nm_dtls_util.h"
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
#include <string.h>

np_error_code nm_dtls_util_fp_from_crt(const mbedtls_x509_crt* crt, uint8_t* fp)
{
    uint8_t buffer[256];
    uint8_t fullSha[32];

    mbedtls_pk_context *ctx = (mbedtls_pk_context*)(&crt->pk);
    int len = mbedtls_pk_write_pubkey_der( ctx, buffer, sizeof(buffer));
    if (len <= 0) {
        return NABTO_EC_FAILED;
    }
    mbedtls_sha256_ret(buffer+sizeof(buffer)-len, len, fullSha, 0);
    memcpy(fp, fullSha, 16);
    return NABTO_EC_OK;
}

np_error_code nm_dtls_create_crt_from_private_key(const char* privateKey, char** publicKey)
{
    // 1. load key from pem
    // 2. create crt
    // 3. write crt to pem string.
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;

    int ret;

    *publicKey = NULL;

    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509write_crt_init(&crt);
    mbedtls_mpi_init(&serial);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    ret = mbedtls_pk_parse_key( &key, (const unsigned char*)privateKey, strlen(privateKey)+1, NULL, 0 );
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    // initialize crt
    mbedtls_x509write_crt_set_subject_key( &crt, &key );
    mbedtls_x509write_crt_set_issuer_key( &crt, &key );

    ret = mbedtls_mpi_read_string( &serial, 10, "1");
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    mbedtls_x509write_crt_set_serial( &crt, &serial );

    ret = mbedtls_x509write_crt_set_subject_name( &crt, "CN=nabto" );
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    ret = mbedtls_x509write_crt_set_issuer_name( &crt, "CN=nabto" );
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    mbedtls_x509write_crt_set_version( &crt, 2 );
    mbedtls_x509write_crt_set_md_alg( &crt, MBEDTLS_MD_SHA256 );

    ret = mbedtls_x509write_crt_set_validity( &crt, "20010101000000", "20491231235959" );
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    ret = mbedtls_x509write_crt_set_basic_constraints( &crt, 1, -1);
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }

    {
        // write crt
        char buffer[1024];
        memset(buffer, 0, 1024);
        ret = mbedtls_x509write_crt_pem( &crt, (unsigned char*)buffer, 1024,
                                         mbedtls_ctr_drbg_random, &ctr_drbg );

        if (ret != 0) {
            return false;
        }
        *publicKey = strdup(buffer);
    }

    // TODO cleanup in case of error
    mbedtls_x509write_crt_free(&crt);
    mbedtls_mpi_free(&serial);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&key);
    if (*publicKey == NULL) {
        return NABTO_EC_FAILED;
    }
    return NABTO_EC_OK;

}


np_error_code nm_dtls_get_fingerprint_from_private_key(const char* privateKey, char** fingerprint)
{
    *fingerprint = NULL;
    mbedtls_pk_context key;
    int ret;

    mbedtls_pk_init(&key);
    ret = mbedtls_pk_parse_key( &key, (const unsigned char*)privateKey, strlen(privateKey)+1, NULL, 0 );
    if (ret != 0) {
        return NABTO_EC_FAILED;
    }
    {
        // get fingerprint
        uint8_t buffer[256];
        uint8_t hash[32];
        // !!! The key is written to the end of the buffer
        int len = mbedtls_pk_write_pubkey_der( &key, buffer, sizeof(buffer));
        if (len <= 0) {
            return NABTO_EC_FAILED;
        }

        ret = mbedtls_sha256_ret(buffer+256 - len,  len, hash, false);
        if (ret != 0) {
            return NABTO_EC_FAILED;
        }

        *fingerprint = malloc(33);
        memset(*fingerprint, 0, 33);
        sprintf(*fingerprint, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                hash[0], hash[1], hash[2],  hash[3],  hash[4],  hash[5],  hash[6],  hash[7],
                hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]);

    }
    mbedtls_pk_free(&key);
    return NABTO_EC_OK;
}

np_error_code nm_dtls_util_create_private_key(char** privateKey)
{
    *privateKey = NULL;
    unsigned char output_buf[1024];
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";

    memset(output_buf, 0, 1024);
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
        (mbedtls_pk_write_key_pem( &key, output_buf, 1024 ) != 0 ))
    {
        // generating the private key failed
    } else {
        *privateKey = strdup((char*)output_buf);
    }

    mbedtls_pk_free( &key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return NABTO_EC_OK;
}
