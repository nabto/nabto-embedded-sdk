#include <nabto/nabto_device_test.h>

#include <stdio.h>

int main()
{
    // instead of calling nabto_device_new, we call
    // nabto_device_test_new to get a test instance with limited
    // functionality.
    NabtoDevice* device = nabto_device_test_new();

    NabtoDeviceFuture* future = nabto_device_future_new(device);

    // Run the DNS test. The test passes if the future resolves and
    // the status of the future is NABTO_DEVICE_EC_OK
    nabto_device_test_dns(device, future);

    NabtoDeviceError ec = nabto_device_future_wait(future);
    if (ec == NABTO_DEVICE_EC_OK) {
        printf("DNS test has passed\n");
    } else {
        printf("DNS test has failed\n");
    }

    nabto_device_future_free(future);
    nabto_device_test_free(device);
}
