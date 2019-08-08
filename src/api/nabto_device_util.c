
#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "nabto_device_threads.h"
#include "nabto_device_defines.h"

#include <stdlib.h>

#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"


void NABTO_DEVICE_API nabto_device_string_free(char* str)
{
    free(str);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_experimental_util_create_private_key(NabtoDevice* device, char** privateKey)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    *privateKey = NULL;
    nabto_device_threads_mutex_lock(dev->eventMutex);
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

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}
