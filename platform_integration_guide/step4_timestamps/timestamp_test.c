#include <nabto/nabto_device_test.h>

#include <stdio.h>

int main()
{
    // instead of calling nabto_device_new, we call
    // nabto_device_test_new to get a test instance with limited
    // functionality.
    NabtoDevice* device = nabto_device_test_new();

    // test that we can get a timestamp from the timestamp
    // implementation we have added to the device.
    uint32_t timestamp;
    nabto_device_test_timestamp(device, &timestamp);

    printf("Timestamp in milliseconds is: %u\n", timestamp);
    printf("Test passes if the returned timestamp is correct.\n");

    nabto_device_test_free(device);
}
