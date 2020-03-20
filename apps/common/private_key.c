#include "private_key.h"

#include "string_file.h"

#include <stdio.h>


static bool create_private_key(NabtoDevice* device, const char* filename)
{
    char* privateKey;
    NabtoDeviceError ec = nabto_device_create_private_key(device, &privateKey);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    bool status = string_file_save(filename, privateKey);

    nabto_device_string_free(privateKey);
    return status;
}

bool load_or_create_private_key(NabtoDevice* device, const char* filename, char** privateKey, const char** errorText)
{
    if (!string_file_exists(filename)) {
        if (!create_private_key(device, filename)) {
            *errorText = "Could not create a new private key file";
            return false;
        }
    }

    bool status = string_file_load(filename, privateKey);
    if (status == false) {
        *errorText = "Could not load private key from file";
        return false;
    }

    return true;
}
