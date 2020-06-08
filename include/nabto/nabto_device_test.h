#ifndef _NABTO_DEVICE_TEST_H_
#define _NABTO_DEVICE_TEST_H_

#include "nabto_device.h"

/**
 * Test functionality. This is used to for selftesting the system and
 * for testing integrations in smaller steps.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Test that the log system works.
 *
 * The log system works. The test creates the following 4 log lines,
 * which can vary a bit depending on the log formatter used.
 *
250.989 .../api/nabto_device_test.c(013)[ERROR] Test ERROR, int: 42, string: test, double: 42.200000
250.989 .../api/nabto_device_test.c(014)[_WARN] Test WARN, int: 42, string: test, double: 42.200000
250.989 .../api/nabto_device_test.c(015)[_INFO] Test INFO, int: 42, string: test, double: 42.200000
250.989 .../api/nabto_device_test.c(016)[TRACE] Test TRACE, int: 42, string: test, double: 42.200000
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_logging(NabtoDevice* device);


/**
 * Test that futures can be resolved.
 *
 * This function resolves the future with NABTO_DEVICE_EC_OK.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_future_resolve(NabtoDevice* device, NabtoDeviceFuture* future);

/**
 * Test that the event queue works.
 *
 * The future is resolved with NABTO_DEVICE_EC_OK if the event queue
 * passes the tests.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_event_queue(NabtoDevice* device, NabtoDeviceFuture* future);

/**
 * Timestamp test
 *
 * The test passes if the future resolves with NABTO_DEVICE_EC_OK
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_timestamp(NabtoDevice* device, NabtoDeviceFuture* future);

/**
 * DNS test
 *
 * This test that the device can resolve dns addresses.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_dns(NabtoDevice* device, NabtoDeviceFuture* future);


/**
 * UDP ipv4 test
 *
 * This test connects to the udp server in the arguments and echoes
 * some data.
 */
/* NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API */
/* nabto_device_test_udp_ipv4(NabtoDevice* device, const char* ipv4Address, uint16_t port, NabtoDeviceFuture* future); */



#ifdef __cplusplus
} // extern "C"
#endif


#endif
