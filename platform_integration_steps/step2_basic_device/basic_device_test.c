#include <nabto/nabto_device_test.h>

#include <stdio.h>

static void create_device_test(void);
static void future_test(void);


int main()
{
    create_device_test();
    future_test();
}

void create_device_test()
{
    // instead of calling nabto_device_new, we call
    // nabto_device_test_new to get a test instance with limited
    NabtoDevice* device = nabto_device_test_new();
    if (device != NULL) {
        printf("Create device test passed\n");
    } else {
        printf("Create device test failed, could not create device.\n");
    }
    nabto_device_test_free(device);
}

void future_test()
{
    NabtoDevice* device = nabto_device_test_new();
    if (device == NULL) {
        printf("Test failed, device is NULL\n");
        return;
    }

    NabtoDeviceFuture* future = nabto_device_future_new(device);
    if (future == NULL) {
        printf("Test failed future is NULL\n");
        return;
    }

    nabto_device_test_future_resolve(device, future);

    // This call blocks until the future is resolved. If the test is
    // not blocking forever and returning NABTO_DEVICE_EC_OK, then the
    // test has passed.
    NabtoDeviceError ec = nabto_device_future_wait(future);

    if (ec == NABTO_DEVICE_EC_OK) {
        printf("Future resolve test has passed\n");
    } else {
        printf("Future resolve test has failed\n");
    }

    nabto_device_test_free(device);
}
