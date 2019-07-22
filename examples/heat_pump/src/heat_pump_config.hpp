#ifndef _HEAT_PUMP_CONFIG_H_
#define _HEAT_PUMP_CONFIG_H_

#include <stdbool.h>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

bool heat_pump_config_exists(const std::string& filename);
bool heat_pump_load_config(const std::string& fileName, json& config);
bool heat_pump_save_config(const std::string& fileName, const std::string& tmpFile, const json& config);

#endif
