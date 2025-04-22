#ifndef JSON_CONFIG_H_
#define JSON_CONFIG_H_

#include <cjson/cJSON.h>
#include <stdbool.h>

#include <modules/fs/nm_fs.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nn_log;

bool json_config_exists(struct nm_fs* fsImpl, const char* fileName);
bool json_config_load(struct nm_fs* fsImpl, const char* fileName, cJSON** config, struct nn_log* logger);
bool json_config_save(struct nm_fs* fsImpl, const char* fileName, cJSON* config);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
