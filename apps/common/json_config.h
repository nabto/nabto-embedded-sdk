#ifndef _JSON_CONFIG_H_
#define _JSON_CONFIG_H_

#include <stdbool.h>
#include <cjson/cJSON.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nn_log;

bool json_config_exists(const char* fileName);
bool json_config_load(const char* fileName, cJSON** config, struct nn_log* logger);
bool json_config_save(const char* fileName, cJSON* config);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
