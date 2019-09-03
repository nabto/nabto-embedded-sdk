#pragma once

#include <stdbool.h>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

bool json_config_exists(const std::string& filename);
bool json_config_load(const std::string& fileName, json& config);
bool json_config_save(const std::string& fileName, const json& config);
