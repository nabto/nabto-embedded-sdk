#include "create_keypair.h"

#include <gopt/gopt.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

struct config {
    const char* productId;
    const char* deviceId;
};

static struct config config;

#define NEWLINE "\n"

void print_help(const char* message)
{
    if (message) {
        printf(message);
        printf(NEWLINE);
    }
    printf("test_device" NEWLINE);
    printf(" USAGE test_device -p <productId> -d <deviceId>" NEWLINE);
}

bool parse_args(int argc, const char** argv)
{
    const char* productId;
    const char* deviceId;

    const char* helpLong[] = { "help", 0 };
    const char* productLong[] = { "product", 0 };
    const char* deviceLong[] = { "device", 0 };

    const struct { int key; int format; const char* shortName; const char*const* longNames; } opts[] = {
        { 1, GOPT_NOARG, "h", helpLong },
        { 2, GOPT_ARG, "p", productLong },
        { 3, GOPT_ARG, "d", deviceLong },
        {0,0,0,0}
    };

    void *options = gopt_sort( & argc, argv, opts);
    if( gopt( options, 1)) {
        print_help(NULL);
        return false;
    }

    if (gopt_arg(options, 2, &productId)) {
        config.productId = productId;
    } else {
        print_help("Missing product id");
        return false;
    }

    if (gopt_arg(options, 3, &deviceId)) {
        config.deviceId = deviceId;
    } else {
        print_help("Missing device id");
        return false;
    }

    return true;
}

bool file_exists(const char* filename)
{
    return (access(filename, R_OK) == 0);
}

bool test_if_certs_exists(const char* crtFilename, const char* keyFilename) {
    if (file_exists(keyFilename) &&
        file_exists(crtFilename))
    {
        return true;
    }
    return false;
}

int main(int argc, const char** argv)
{
    char keyFilename[128];
    char crtFilename[128];
    memset(keyFilename, 0, 128);
    memset(crtFilename, 0, 128);

    memset(&config, 0, sizeof(struct config));
    if (!parse_args(argc, argv)) {
        exit(1);
    }

    snprintf(keyFilename, 127, "%s_%s.key", config.productId, config.deviceId);
    snprintf(crtFilename, 127, "%s_%s.crt", config.productId, config.deviceId);


    if (!test_if_certs_exists(crtFilename, keyFilename)) {
        if (!create_keypair(crtFilename, keyFilename)) {
            printf("FATAL cannot create a new keypair" NEWLINE);
            exit(1);
        }

        printf("Created keypair." NEWLINE);
        printf("Install the fingerprint of the public key of the device into the basestation." NEWLINE);
        // todo print the fignerprint

        printf("Start the device again when the fingerprint has been added to the basestation." NEWLINE);
        exit(1);
    }

    // TODO read crt and key
    // TODO start a device
    // TODO add streaming and coap handlers

}
