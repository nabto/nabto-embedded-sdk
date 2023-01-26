#include "device_config.h"

#include "json_config.h"
#include "prompt_stdin.h"

#include <cjson/cJSON.h>

#include <string.h>
#include <stdlib.h>

#if defined(_WIN32)
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif


static const char* LOGM = "device_config";

bool load_device_config(struct nm_file *fileImpl, const char* fileName, struct device_config* dc, struct nn_log* logger)
{
    cJSON* config;
    if (!json_config_load(fileImpl, fileName, &config, logger)) {
        return false;
    }

    cJSON* productId = cJSON_GetObjectItem(config, "ProductId");
    cJSON* deviceId = cJSON_GetObjectItem(config, "DeviceId");
    cJSON* server = cJSON_GetObjectItem(config, "Server");
    cJSON* serverPort = cJSON_GetObjectItem(config, "ServerPort");

    if (!cJSON_IsString(productId) ||
        !cJSON_IsString(deviceId))
    {
        NN_LOG_ERROR(logger, LOGM, "Missing required device config options");
        return false;
    }

    dc->productId = strdup(productId->valuestring);
    dc->deviceId = strdup(deviceId->valuestring);
    if (cJSON_IsString(server)) {
        dc->server = strdup(server->valuestring);
    }
    if (cJSON_IsNumber(serverPort)) {
        dc->serverPort = (uint16_t)serverPort->valuedouble;
    }

    cJSON_Delete(config);

    return true;
}

bool save_device_config(struct nm_file* fileImpl, const char* fileName, struct device_config* dc)
{
    cJSON* config = cJSON_CreateObject();
    if (dc->productId != NULL) {
        cJSON_AddItemToObject(config, "ProductId", cJSON_CreateString(dc->productId));
    }
    if (dc->deviceId != NULL) {
        cJSON_AddItemToObject(config, "DeviceId", cJSON_CreateString(dc->deviceId));
    }
    if (dc->server != NULL) {
        cJSON_AddItemToObject(config, "Server", cJSON_CreateString(dc->server));
    }
    if (dc->serverPort != 0) {
        cJSON_AddItemToObject(config, "ServerPort", cJSON_CreateNumber(dc->serverPort));
    }
    bool status = json_config_save(fileImpl, fileName, config);
    cJSON_Delete(config);
    return status;
}

void device_config_init(struct device_config* config)
{
    memset(config, 0, sizeof(struct device_config));
}

void device_config_deinit(struct device_config* config)
{
    free(config->productId);
    free(config->deviceId);
    free(config->server);
}

bool create_device_config_interactive(struct nm_file* fileImpl, const char* file)
{
    char productId[20];
    char deviceId[20];
    printf("The device configuration requires a Product ID and a Device ID, created in the Nabto Cloud Console." NEWLINE);
    prompt_repeating("Product Id", productId, ARRAY_SIZE(productId));
    prompt_repeating("Device Id", deviceId, ARRAY_SIZE(deviceId));

    struct device_config dc;
    memset(&dc, 0, sizeof(struct device_config));
    dc.productId = productId;
    dc.deviceId = deviceId;
    return save_device_config(fileImpl, file, &dc);
}
