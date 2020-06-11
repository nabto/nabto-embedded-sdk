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
 * Create a new NabtoDevice instance which can only be used with
 * tests.
 *
 * The test NabtoDevice is allowed to contain an incomplete platform
 * implementation.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDevice* NABTO_DEVICE_API
nabto_device_test_new(void);


/**
 * Free a test NabtoDevice instance.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_free(NabtoDevice* device);

/**
 * Stop a test NabtoDevice instance.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_stop(NabtoDevice* device);

/**
 * Test that the threads implementation works.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_test_threads(void);

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
nabto_device_test_timestamp(NabtoDevice* device, uint32_t* timestamp);

/**
 * DNS test
 *
 * This test that the device can resolve dns addresses.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_dns(NabtoDevice* device, NabtoDeviceFuture* future);


/**
 * UDP test
 *
 * This test connects to the udp server in the arguments and echoes
 * some data.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_udp(NabtoDevice* device, const char* ip, uint16_t port, NabtoDeviceFuture* future);

/**
 * TCP test
 *
 * This test connects to a TCP echo server, sends some data and
 * validates that the data is echoed back again.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_tcp(NabtoDevice* device, const char* ip, uint16_t port, NabtoDeviceFuture* future);

/**
 * Local IP Test
 *
 * This test retrieves the local ip from the system and prints it to
 * the log. The test passes if the correct local ip is written in the
 * log.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_local_ip(NabtoDevice* device);

/**
 * MDNS publish service test
 *
 * This test publishes a _nabto._udp MDNS service. The test passes if
 * the service can be discovered by a MDNS client.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_test_mdns_publish_service(NabtoDevice* device);



#ifdef __cplusplus
} // extern "C"
#endif


#endif
