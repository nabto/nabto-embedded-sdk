#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

int main() {
    NabtoDevice* device = nabto_device_new();
    nabto_device_set_log_std_out_callback(device);

    nabto_device_crypto_speed_test(device);

    nabto_device_free(device);
}
