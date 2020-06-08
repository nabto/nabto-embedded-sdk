/**
 * Test program which uses the tests defined in nabto_device_test.h to
 * test that a platform is integrated properly.
 */

#include <nabto/nabto_device_test.h>

#include <stdio.h>

static void logging_test(void);
static void future_test(void);
static void event_queue_test(void);
static void timestamp_test(void);
static void dns_test(void);
static void udp_test(const char* ip);


int main(int argc, const char* argv[]) {
    logging_test();
    future_test();
    event_queue_test();
    timestamp_test();
    dns_test();


    if (argc >= 2) {
        // first arg is program name, seconds arg should be integration test server.

        udp_test(argv[1]);

    } else {
        printf("Does not test network integration as no integration test server is specified.\n");
    }

}


/**
 * Test the logging system.
 *
 * The tests passes if logs is written to the console output.
 */
void logging_test()
{
    NabtoDevice* device = nabto_device_new();
    nabto_device_set_log_level(device, "trace");
    nabto_device_set_log_std_out_callback(device);
    nabto_device_test_logging(device);
    nabto_device_free(device);
    printf("Logging test passed if logs were seen in the console output\n");
}


/**
 * Test the future system.
 *
 * The test passes if it does not block forever.
 */
void future_test()
{
    NabtoDevice* device = nabto_device_new();
    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_test_future_resolve(device, fut);
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
    nabto_device_free(device);
    printf("Future test passed\n");
}

/**
 * Test the event queue system.
 */
void event_queue_test()
{
    NabtoDevice* device = nabto_device_new();
    NabtoDeviceFuture* future = nabto_device_future_new(device);
    nabto_device_test_event_queue(device, future);
    NabtoDeviceError ec = nabto_device_future_wait(future);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Event queue test failed with error %s\n", nabto_device_error_get_string(ec));
    } else {
        printf("Event queue test passed\n");
    }
    nabto_device_future_free(future);
    nabto_device_free(device);
}

/**
 * Test timestamps
 */
void timestamp_test()
{
    NabtoDevice* device = nabto_device_new();
    NabtoDeviceFuture* future = nabto_device_future_new(device);
    nabto_device_test_timestamp(device, future);
    NabtoDeviceError ec = nabto_device_future_wait(future);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Timestamp test failed with error %s\n", nabto_device_error_get_string(ec));
    } else {
        printf("Timestamp test passed\n");
    }
    nabto_device_future_free(future);
    nabto_device_free(device);
}

/**
 * Test dns resolution
 */
void dns_test()
{
    NabtoDevice* device = nabto_device_new();
    NabtoDeviceFuture* future = nabto_device_future_new(device);
    nabto_device_test_dns(device, future);
    NabtoDeviceError ec = nabto_device_future_wait(future);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("DNS test failed with error %s\n", nabto_device_error_get_string(ec));
    } else {
        printf("DNS test passed\n");
    }
    nabto_device_future_free(future);
    nabto_device_free(device);
}

void udp_test(const char* ip)
{
    NabtoDevice* device = nabto_device_new();
    NabtoDeviceFuture* future = nabto_device_future_new(device);
    nabto_device_test_udp(device, ip, 1234, future);
    NabtoDeviceError ec = nabto_device_future_wait(future);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("UDP IPv4 test failed with error %s\n", nabto_device_error_get_string(ec));
    } else {
        printf("UDP IPV4 test passed\n");
    }
    nabto_device_future_free(future);
    nabto_device_free(device);
}
