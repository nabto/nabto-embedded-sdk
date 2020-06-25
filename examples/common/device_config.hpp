#pragma once

#include "json_config.hpp"
#include <nlohmann/json.hpp>
#include <string>

namespace nabto {
namespace examples {
namespace common {

class DeviceConfig
{
 public:
    DeviceConfig(const std::string& filename)
        : filename_(filename)
    {
    }

    bool load()
    {
        return json_config_load(filename_, config_);
    }

    bool isValid()
    {
        return
            config_["ProductId"].is_string() &&
            config_["DeviceId"].is_string();
    }

    std::string getProductId()
    {
        return config_["ProductId"].get<std::string>();
    }
    std::string getDeviceId()
    {
        return config_["DeviceId"].get<std::string>();
    }
    std::string getServer()
    {
        return config_["Server"].get<std::string>();
    }
    std::string getClientServerUrl()
    {
        try {
            return config_["Client"]["ServerUrl"].get<std::string>();
        } catch (...) {
            return "";
        }
    }
    std::string getClientServerKey()
    {
        try {
            return config_["Client"]["ServerKey"].get<std::string>();
        } catch (...) {
            return "";
        }
    }

    static std::string example()
    {
        std::string exampleDeviceConfig = R"(
{
  "ProductId": "...",
  "DeviceId": "...",
  "Server": "...",
  "Client": {
    "ServerKey": "...",
    "ServerUrl": "..."
  }
}
)";
        return exampleDeviceConfig;

    }

 private:
    std::string filename_;
    nlohmann::json config_;
};

} } } // namespace
