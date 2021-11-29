#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include "nabto_device_threads.h"
#include "nabto_device_defines.h"

#include <platform/np_logging.h>
#include <platform/np_logging_defines.h>
#include <platform/np_timestamp_wrapper.h>

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
    uint32_t start = np_timestamp_now_ms(&dev->pl.timestamp);
    // call SHA256
    uint32_t end = np_timestamp_now_ms(&dev->pl.timestamp);

    int32_t elapsed = np_timestamp_difference(end, start);
    NABTO_LOG_INFO(LOG, "SHA256 took %d ms", elapsed);
}

void p256r1_multiplication_speed_test(struct nabto_device_context* dev) {
    NABTO_LOG_INFO(LOG, "Testing p256r1 multiplication performance");
    uint32_t start = np_timestamp_now_ms(&dev->pl.timestamp);
    // do multiplication
    uint32_t end = np_timestamp_now_ms(&dev->pl.timestamp);

    int32_t elapsed = np_timestamp_difference(end, start);
    NABTO_LOG_INFO(LOG, "p256r1 multiplication took %d ms", elapsed);
}
