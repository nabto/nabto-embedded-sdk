#ifndef DEVICE_CONFIG_H_
#define DEVICE_CONFIG_H_

#include <nn/log.h>

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_fs;

struct device_config {
    char* productId;
    char* deviceId;
    char* server;
    uint16_t serverPort;
};

void device_config_init(struct device_config* config);
void device_config_deinit(struct device_config* config);

bool load_device_config(struct nm_fs *fsImpl, const char* fileName, struct device_config* dc, struct nn_log* logger);
bool save_device_config(struct nm_fs *fsImpl, const char* fileName, struct device_config* dc);

bool create_device_config_interactive(struct nm_fs *fsImpl, const char* file);

#ifdef __cplusplus
} // extern c
#endif

#endif
