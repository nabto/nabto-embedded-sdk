#include "heatpump_config.hpp"

#include <fstream>
#include <cstdio>

bool heatpump_config_exists(const std::string& filename)
{
    std::ifstream configFile(filename);
    return (configFile.is_open() && !configFile.fail());
}

bool heatpump_load_config(const std::string& filename, json& config)
{
    json j;
    try {
        std::ifstream configFile(filename);
        configFile >> j;
    } catch (...) {
        return false;
    }
    config = j;
    return true;
}

bool heatpump_save_config(const std::string& filename, const std::string& tmpFile, const json& config)
{
    bool status = false;
    std::remove(tmpFile.c_str());
    try {
        std::ofstream configFile(tmpFile);
        configFile << config.dump(2);
        std::rename(tmpFile.c_str(), filename.c_str());
        status = true;
    } catch (...) {
    }

    try {
        std::remove(tmpFile.c_str());
    } catch (...) {

    }
    return status;
}
