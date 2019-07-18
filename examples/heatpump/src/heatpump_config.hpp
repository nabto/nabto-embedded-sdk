#ifndef _HEATPUMP_CONFIG_H_
#define _HEATPUMP_CONFIG_H_

#include <stdbool.h>
#include <nabto/nabto_device.h>

struct heatpump_config {
    char* hostname;
    char* deviceId;
    char* productId;
    char* productName;
    char* privateKey;
};

bool heatpump_config_has_private_key();
bool heatpump_config_read_private_key(NabtoDevice* device);
bool heatpump_config_create_new_private_key(NabtoDevice* device);


#endif
