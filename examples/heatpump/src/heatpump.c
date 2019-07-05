#include <gopt/gopt.h>

#include <nabto/nabto_device.h>
#include "heatpump_config.h"

#include <stdio.h>
#include <stdlib.h>

void print_help(const char* message);
bool parse_args(int argc, const char** argv, NabtoDevice* device);
bool initialize_application(int argc, const char** argv, NabtoDevice* device);

#if defined(WIN32)
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif

void print_help(const char* message)
{
    if (message) {
        printf("%s", message);
        printf(NEWLINE);
    }
    printf("test_device version %s" NEWLINE, nabto_device_version());
    printf(" USAGE test_device -p <productId> -d <deviceId> -k <keyfile> --hostname <hostname>" NEWLINE);
}


bool initialize_application(int argc, const char** argv, NabtoDevice* device)
{
    if (!heatpump_config_has_private_key()) {
        printf("No private key exists creating a new private key\n");
        if (!heatpump_config_create_new_private_key(device)) {
            printf("Could not create a new private key\n");
            return false;
        }
    } else {

    }

    if (!heatpump_config_read_private_key(device)) {
        printf("Could not read private key from file\n");
        return false;
    }

    if (!parse_args(argc, argv, device)) {
        return false;
    }

    NabtoDeviceError ec = nabto_device_start(device);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Failed to start device\n");
        return false;
    }

    return true;
}


bool parse_args(int argc, const char** argv, NabtoDevice* device)
{
    const char* productId;
    const char* deviceId;
    const char* hostname;

    const char* helpLong[] = { "help", 0 };
    const char* productLong[] = { "product", 0 };
    const char* deviceLong[] = { "device", 0 };
    const char* hostnameLong[] = { "hostname", 0 };

    const struct { int key; int format; const char* shortName; const char*const* longNames; } opts[] = {
        { 1, GOPT_NOARG, "h", helpLong },
        { 2, GOPT_ARG, "p", productLong },
        { 3, GOPT_ARG, "d", deviceLong },
        { 5, GOPT_ARG, "", hostnameLong },
        {0,0,0,0}
    };

    void *options = gopt_sort( & argc, argv, opts);
    if( gopt( options, 1)) {
        print_help(NULL);
        return false;
    }

    if (gopt_arg(options, 2, &productId) &&
        nabto_device_set_product_id(device, productId) == NABTO_DEVICE_EC_OK)
    {
        // ok
    } else {
        print_help("Missing product id");
        return false;
    }

    if (gopt_arg(options, 3, &deviceId) &&
        nabto_device_set_device_id(device, deviceId) == NABTO_DEVICE_EC_OK)
    {
        // ok
    } else {
        print_help("Missing device id");
        return false;
    }

    if (gopt_arg(options, 5, &hostname) &&
        nabto_device_set_server_url(device, hostname) == NABTO_DEVICE_EC_OK)
    {
        // ok
    } else {
        print_help("Missing hostname");
        return false;
    }

    return true;
}

int main(int argc, const char** argv) {
    printf("Initializing Heatpump\n");

    NabtoDevice* device = nabto_device_new();

    // initilize application
    if (!initialize_application(argc, argv, device)) {
        printf("Initialization failed\n");
        exit(1);
    } else {
        printf("Application initialized\n");
    }

    // run application

    printf("Press enter to stop\n");
    int c = 0;
    while (c != '\n') {
        c = getchar();
    }
    nabto_device_free(device);
}
