#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include "nabto_device_threads.h"
#include "nabto_device_defines.h"

#include <platform/np_logging.h>
#include <platform/np_logging_defines.h>
#include <platform/np_timestamp_wrapper.h>

#include <mbedtls/sha256.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>

#define LOG NABTO_LOG_MODULE_PLATFORM

static void sha256_speed_test(struct nabto_device_context* dev);
static void p256r1_multiplication_speed_test(struct nabto_device_context* dev);

NabtoDeviceError NABTO_DEVICE_API
nabto_device_crypto_speed_test(NabtoDevice* device) {
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    sha256_speed_test(dev);
    p256r1_multiplication_speed_test(dev);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}


void sha256_speed_test(struct nabto_device_context* dev) {
    NABTO_LOG_INFO(LOG, "Testing SHA256 performance");
    uint8_t data[1024];
    uint8_t output[32];

    size_t iterations = 1000;

    uint32_t start = np_timestamp_now_ms(&dev->pl.timestamp);

    for (size_t i = 0; i < iterations; i++) {
        mbedtls_sha256(data, sizeof(data), output, 0);
    }

    uint32_t end = np_timestamp_now_ms(&dev->pl.timestamp);

    int32_t elapsed = np_timestamp_difference(end, start);
    NABTO_LOG_INFO(LOG, "SHA256 took %d ms for %d rounds of size %d each", elapsed, iterations, sizeof(data));
}

void p256r1_multiplication_speed_test(struct nabto_device_context* dev) {
    NABTO_LOG_INFO(LOG, "Testing p256r1 multiplication performance");

    // do multiplication

    int status;
    // calculcate Q = d*G where d is a bignumber and G is the generator for the group P256r1

    uint8_t number[32];
    struct np_platform* pl = &dev->pl;
    pl->random.random(pl, &number, sizeof(number));

    mbedtls_mpi d;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;

    mbedtls_mpi_init(&d);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);

    status = mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP256R1);
    if (status != 0) {
        NABTO_LOG_ERROR(LOG, "cannot load the group P256R1");
        return;
    }

    mbedtls_mpi_read_binary(&d, number, sizeof(number));

    // Q = dG
    uint32_t start = np_timestamp_now_ms(&dev->pl.timestamp);
    {
        status = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, NULL, NULL);
        if (status != 0) {
            NABTO_LOG_ERROR(LOG, "failed to do multiplication");
            return;
        }
    }
    uint32_t end = np_timestamp_now_ms(&dev->pl.timestamp);

    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);

    int32_t elapsed = np_timestamp_difference(end, start);
    NABTO_LOG_INFO(LOG, "p256r1 multiplication took %d ms", elapsed);
}
