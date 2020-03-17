#ifndef _DEVICE_CONFIG_H_
#define _DEVICE_CONFIG_H_

#include <stdbool.h>

struct device_config {
    char* productId;
    char* deviceId;
    char* server;
    char* clientServerKey;
    char* clientServerUrl;
};

void device_config_init(struct device_config* config);
void device_config_deinit(struct device_config* config);

bool load_device_config(const char* fileName, struct device_config* dc, const char** errorText);

#endif
