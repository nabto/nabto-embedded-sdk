#include <nabto/nabto_device.h>

#include <stdio.h>

int main()
{
    NabtoDeviceError ec = nabto_device_test_threads();
    if (ec == NABTO_DEVICE_EC_OK) {
        printf("Threads test passed\n");
    } else {
        printf("Threads test failed\n");
    }
}
