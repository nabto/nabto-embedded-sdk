#include "create_keypair.h"

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

#include <string.h>

static bool write_file(const char* filename, uint8_t* content, size_t contentLength)
{
    FILE* f;
    f = fopen( filename, "wb" );
    if(f == NULL) {
        return false;
    }

    if(fwrite( content, 1, contentLength, f ) != contentLength) {
        fclose( f );
        return false;
    }

    fclose(f);
    return true;
}

bool create_keypair(const char* crtFileName, const char* keyFileName)
{
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    uint8_t buffer[1024];
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    int ret;

    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509write_crt_init(&crt);
    mbedtls_mpi_init(&serial);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        return false;
    }
    ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        return false;
    }
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key),
                              mbedtls_ctr_drbg_random, &ctr_drbg);

    // initialize crt
    mbedtls_x509write_crt_set_subject_key( &crt, &key );
    mbedtls_x509write_crt_set_issuer_key( &crt, &key );
    ret = mbedtls_mpi_read_string( &serial, 10, "1");
    if (ret != 0) {
        return false;
    }
    mbedtls_x509write_crt_set_serial( &crt, &serial );

    ret = mbedtls_x509write_crt_set_subject_name( &crt, "CN=nabto" );
    if (ret != 0) {
        return false;
    }

    ret = mbedtls_x509write_crt_set_issuer_name( &crt, "CN=nabto" );
    if (ret != 0) {
        return false;
    }

    mbedtls_x509write_crt_set_version( &crt, 2 );
    mbedtls_x509write_crt_set_md_alg( &crt, MBEDTLS_MD_SHA256 );

    ret = mbedtls_x509write_crt_set_validity( &crt, "20010101000000", "20491231235959" );
    if (ret != 0) {
        return false;
    }

    ret = mbedtls_x509write_crt_set_basic_constraints( &crt, 1, -1);
    if (ret != 0) {
        return false;
    }

    {
        // write private key
        memset(buffer, 0, 1024);
        size_t len = 0;

        ret = mbedtls_pk_write_key_pem( &key, buffer, 1024 );
        if(ret != 0) {
            return false;
        }

        len = strlen( (char *) buffer );
        if (!write_file(keyFileName, buffer, len)) {
            return false;
        }
    }
    {
        // write crt
        memset(buffer, 0, 1024);
        size_t len = 0;

        ret = mbedtls_x509write_crt_pem( &crt, buffer, 1024,
                                         mbedtls_ctr_drbg_random, &ctr_drbg );

        if (ret != 0) {
            return false;
        }

        len = strlen( (char *) buffer );
        if (!write_file(crtFileName, buffer, len)) {
            return false;
        }
    }

    mbedtls_x509write_crt_free( &crt );
    mbedtls_mpi_free( &serial );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_pk_free( &key );
    return true;
}
