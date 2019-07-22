#ifndef _HEATPUMP_CONFIG_H_
#define _HEATPUMP_CONFIG_H_

#include <stdbool.h>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

bool heatpump_config_exists(const std::string& filename);
bool heatpump_load_config(const std::string& fileName, json& config);
bool heatpump_save_config(const std::string& fileName, const std::string& tmpFile, const json& config);

#endif
