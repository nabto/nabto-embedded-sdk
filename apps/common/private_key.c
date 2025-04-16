#include "private_key.h"

#include "string_file.h"

#include <stdio.h>
#include <stdlib.h>

static const char* LOGM = "private_key";

bool create_private_key(NabtoDevice* device, struct nm_fs* fsImpl, const char* filename, struct nn_log* logger)
{
    char* privateKey = NULL;
    NabtoDeviceError ec = nabto_device_create_private_key(device, &privateKey);
    if (ec != NABTO_DEVICE_EC_OK) {
        NN_LOG_ERROR(logger, LOGM, "Could not generate a new private key. %s", nabto_device_error_get_message(ec));
        return false;
    }
    bool status = string_file_save(fsImpl, filename, privateKey);

    nabto_device_string_free(privateKey);
    return status;
}

bool load_or_create_private_key(NabtoDevice* device, struct nm_fs* fsImpl,const char* filename, struct nn_log* logger)
{
    if (!string_file_exists(fsImpl, filename)) {
        if (!create_private_key(device, fsImpl, filename, logger)) {
            NN_LOG_ERROR(logger, LOGM, "The private key file (%s) could not be created", filename);
            return false;
        }
    }

    char* privateKey = NULL;
    bool status = string_file_load(fsImpl, filename, &privateKey);
    if (status == false) {
        NN_LOG_ERROR(logger, LOGM, "The private key could not be loaded from the key file %s", filename);
        return false;
    }

    NabtoDeviceError ec = nabto_device_set_private_key(device, privateKey);
    free(privateKey);
    if (ec != NABTO_DEVICE_EC_OK) {
        NN_LOG_ERROR(logger, LOGM, "The private key (%s) could not be loaded, is it in the right format?", filename);
        return false;
    }

    return true;
}
