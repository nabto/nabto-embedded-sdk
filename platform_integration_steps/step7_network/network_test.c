#include <nabto/nabto_device_test.h>

#include <stdio.h>

static void udp_test(const char* testServerHost, uint16_t testServerPort);
static void tcp_test(const char* testServerHost, uint16_t testServerPort);

int main()
{
    const char* testServerHost = "127.0.0.1";
    uint16_t testServerPort = 1234;
    udp_test(testServerHost, testServerPort);
    tcp_test(testServerHost, testServerPort);
}


void udp_test(const char* testServerHost, uint16_t testServerPort) {
    NabtoDevice* device = nabto_device_test_new();
    NabtoDeviceFuture* future = nabto_device_future_new(device);

    // Run the UDP test. The test passes if the future resolves and
    // the status of the future is NABTO_DEVICE_EC_OK
    nabto_device_test_udp(device, testServerHost, testServerPort, future);

    NabtoDeviceError ec = nabto_device_future_wait(future);
    if (ec == NABTO_DEVICE_EC_OK) {
        printf("UDP test has passed\n");
    } else {
        printf("UDP test has failed\n");
    }

    nabto_device_future_free(future);
    nabto_device_test_free(device);
}


void tcp_test(const char* testServerHost, uint16_t testServerPort) {
    NabtoDevice* device = nabto_device_test_new();
    NabtoDeviceFuture* future = nabto_device_future_new(device);

    // Run the TCP test. The test passes if the future resolves and
    // the status of the future is NABTO_DEVICE_EC_OK
    nabto_device_test_tcp(device, testServerHost, testServerPort, future);

    NabtoDeviceError ec = nabto_device_future_wait(future);
    if (ec == NABTO_DEVICE_EC_OK) {
        printf("TCP test has passed\n");
    } else {
        printf("TCP test has failed\n");
    }

    nabto_device_future_free(future);
    nabto_device_test_free(device);
}
