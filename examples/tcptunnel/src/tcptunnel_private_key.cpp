#include "tcptunnel_private_key.hpp"

#include <nabto/nabto_device.h>

#include <examples/common/json_config.hpp>
#include <nlohmann/json.hpp>
#include <string>
#include <iostream>

static bool try_load_private_key(const std::string& keyfileName, std::string& privateKey);
static bool create_private_key(const std::string& keyfileName);

bool try_load_private_key(const std::string& keyFileName, std::string& privateKey)
{
    nlohmann::json content;
    if (!json_config_load(keyFileName, content)) {
        return false;
    }

    nlohmann::json pk = content["PrivateKey"];
    if (!pk.is_string()) {
        return false;
    }

    privateKey = pk.get<std::string>();
    return true;
}

bool create_private_key(const std::string& keyFileName)
{
    std::cout << "creating a new private key with the filename " << keyFileName << std::endl;
    NabtoDevice* device = nabto_device_new();

    char* privateKey;
    if (nabto_device_create_private_key(device, &privateKey) != NABTO_DEVICE_EC_OK) {
        nabto_device_free(device);
        return false;
    }

    nlohmann::json root;
    root["PrivateKey"] = std::string(privateKey);

    nabto_device_string_free(privateKey);
    json_config_save(keyFileName, root);
    nabto_device_free(device);
    return true;
}

bool load_private_key(const std::string& keyfileName, std::string& privateKey)
{
    if (try_load_private_key(keyfileName, privateKey)) {
        return true;
    }
    if (!create_private_key(keyfileName)) {
        return false;
    }
    return try_load_private_key(keyfileName, privateKey);
}
