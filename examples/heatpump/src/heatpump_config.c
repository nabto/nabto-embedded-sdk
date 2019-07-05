#include "heatpump_config.h"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <cjson/cJSON.h>

#include <stdio.h>
#include <stdlib.h>



static const char* privateKeyFilename = "key.pem";

static char* heatpump_read_file(const char* file);

bool heatpump_config_has_private_key()
{
    FILE* file = fopen(privateKeyFilename, "rb");
    if (!file) {
        return false;
    }
    fclose(file);
    return true;
}

bool heatpump_config_read_private_key(NabtoDevice* device)
{
    char* data = heatpump_read_file("key.pem");
    if (data) {
        nabto_device_set_private_key(device, data);
        free(data);
        return true;
    }
    return false;
}

bool heatpump_config_create_new_private_key(NabtoDevice* device)
{
    NabtoDeviceError status;
    char* privateKey = nabto_device_experimental_util_create_private_key(device);
    status = nabto_device_set_private_key(device, privateKey);
    if (status != NABTO_DEVICE_EC_OK) {
        return false;
    }
    nabto_device_experimental_util_free(privateKey);
    return true;
}

void heatpump_config_init(struct heatpump_config* config) {
    memset(config, 0, sizeof(struct heatpump_config));
}

void heatpump_config_free(struct heatpump_config* config) {
    free(config->hostname);
    free(config->deviceId);
    free(config->productId);
    free(config->productName);
    free(config->privateKey);
}

char* heatpump_read_file(const char* filename)
{
    size_t len = 0;
    char* data = NULL;
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return data;
    }

    /* get the length */
    fseek(file, 0, SEEK_END);
    len = ftell(file);
    fseek(file, 0, SEEK_SET);

    data = (char*)malloc(len + 1);

    fread(data, 1, len, file);
    data[len] = '\0';
    fclose(file);
    return data;
}


/* bool parseSettings(struct heatpump_config* config, cJSON* root) */
/* { */
/*     /\* const cJSON* hostname = NULL; *\/ */
/*     /\* const cJSON* deviceId = NULL; *\/ */
/*     /\* const cJSON* productId = NULL; *\/ */
/*     /\* const cJSON* productName = NULL; *\/ */
/*     /\* const cJSON* privateKey = NULL; *\/ */
/* } */

/* bool readSettingsJson(struct heatpump_config* config, char* json) */
/* { */
/*     cJSON* root = cJSON_Parse(json); */
/*     if (root == NULL) { */
/*         return false; */
/*     } */
/*     bool status = parseSettings(config, root); */
/*     cJSON_Delete(root); */
/*     return status; */
/* } */


/* bool readSettingsFile(struct heatpump_config* config, const char* settingsFile) */
/* { */
/*     char* settingsData = readFile(settingsFile); */
/*     status = readSettingsJson(config, file); */
/*     free(settingsData); */
/*     return status; */
/* } */
