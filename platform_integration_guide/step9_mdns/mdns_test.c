#include <nabto/nabto_device_test.h>

#include <stdio.h>

#include <unistd.h>

int main()
{
    NabtoDevice* device = nabto_device_test_new();

    nabto_device_test_mdns_publish_service(device);
    printf("Test passes if the _nabto._udp mdns service can be discovered by a mdns client\n");

    // wait for someone to break with CTRL-C and leak memory, to keep
    // the test code simple.
    while(true) {
        sleep(1);
    }
}
