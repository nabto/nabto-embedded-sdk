//
// Simple example to demonstrate a Nabto Edge mDNS enabled device. Combine with other examples to
// achieve anything in addition to just service discovery. See the Nabto Edge tunnel app for a full
// example.
//

#include <nabto/nabto_device.h>
#include <apps/common/string_file.h>

#ifdef _WIN32
#include <Windows.h>
#define NEWLINE "\r\n"
#else
#include <unistd.h>
#define NEWLINE "\n"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

void die(const char* msg) {
    printf("%s" NEWLINE, msg);
    exit(1);
}

int main(int argc, char* argv[]) {

    if (argc != 6) {
        printf("The example takes exactly 5 arguments: %s <product-id> <device-id> <mdns subtype> <mdns txt key> <mdns txt value>" NEWLINE, argv[0]);
        return -1;
    }

    char* productId = argv[1];
    char* deviceId = argv[2];
    char* subType = argv[3];
    char* txtKey = argv[4];
    char* txtVal = argv[5];

    NabtoDevice* device = NULL;

    printf("Nabto Embedded SDK Version %s\n", nabto_device_version());

    if ((device = nabto_device_new()) == NULL) {
        die("Allocation error");
    }

    char *key = NULL;
    if (nabto_device_create_private_key(device, &key) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_private_key(device, key) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_product_id(device, productId) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_device_id(device, deviceId) != NABTO_DEVICE_EC_OK ||
        //nabto_device_set_log_level(device, "trace") != NABTO_DEVICE_EC_OK ||
        nabto_device_set_local_port(device, 5592) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_log_std_out_callback(device) != NABTO_DEVICE_EC_OK ||
        // mDNS specifics:
        nabto_device_enable_mdns(device) != NABTO_DEVICE_EC_OK ||
        nabto_device_mdns_add_subtype(device, subType) != NABTO_DEVICE_EC_OK ||
        nabto_device_mdns_add_txt_item(device, txtKey, txtVal) != NABTO_DEVICE_EC_OK ||
        nabto_device_mdns_add_txt_item(device, "nabto_version", nabto_device_version()) != NABTO_DEVICE_EC_OK)

    {
        die("Device setup error");
    }

    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_start(device, fut);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    if (ec != NABTO_DEVICE_EC_OK) {
        die("Start failed");
    }

    printf("Device is now mDNS discoverable, press enter to cleanly stop.\n");
    getchar();

    nabto_device_string_free(key);
    nabto_device_stop(device);
    nabto_device_free(device);
    nabto_device_future_free(fut);

    printf("Device cleaned up and closing\n");
    return 0;
}
