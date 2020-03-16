#ifndef _JSON_CONFIG_H_
#define _JSON_CONFIG_H_

#include <stdbool.h>
#include <cjson/cJSON.h>

bool json_config_exists(const char* fileName);
bool json_config_load(const char* fileName, cJSON** config);
bool json_config_save(const char* fileName, cJSON* config);

#endif
