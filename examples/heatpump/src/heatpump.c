

#include <nabto/nabto_device.h>
#include "heatpump_config.h"

#include <stdio.h>
#include <stdlib.h>

bool initialize_application(NabtoDevice* device)
{
    if (!heatpump_config_has_private_key()) {
        printf("No private key exists creating a new private key\n");
        if (!heatpump_config_create_new_private_key(device)) {
            printf("Could not create a new private key\n");
            return false;
        }
    }

    if (!heatpump_config_read_private_key(device)) {
        printf("Could not read private key from file\n");
        return false;
    }
    return true;
}

int main(int argc, const char** argv) {
    printf("Initializing Heatpump\n");

    NabtoDevice* device = nabto_device_new();

    // initilize application
    if (!initialize_application(device)) {
        printf("Initialization failed\n");
        exit(1);
    }

    // run application

    nabto_device_free(device);
}
