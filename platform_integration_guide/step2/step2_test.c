#include <nabto/nabto_device_test.h>

#include <stdio.h>

int main()
{
    // instead of calling nabto_device_new, we call
    // nabto_device_test_new to get a test instance with limited
    NabtoDevice* device = nabto_device_test_new();
    if (device != NULL) {
        printf("Test passed\n");
    } else {
        printf("Test failed, could not create device.\n");
    }
    nabto_device_test_free(device);
}
