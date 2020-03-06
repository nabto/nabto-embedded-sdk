#include "private_key.hpp"

#include <nabto/nabto_device.h>

#include <examples/common/json_config.hpp>
#include <nlohmann/json.hpp>
#include <string>
#include <iostream>
#include <fstream>

static bool try_load_private_key(const std::string& keyfileName, std::string& privateKey);
static bool create_private_key(const std::string& keyfileName);

bool private_key_exists(const std::string& keyFileName)
{
    std::ifstream file(keyFileName);
    return (file.is_open() && !file.fail());
}

bool try_load_private_key(const std::string& keyFileName, std::string& privateKey)
{
    if (!private_key_exists(keyFileName)) {
        return false;
    }
    try {
        std::ifstream configFile(keyFileName);
        privateKey = std::string((std::istreambuf_iterator<char>(configFile)),
                                 std::istreambuf_iterator<char>());
        return true;
    } catch (...) {
        return false;
    }
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

    std::string privateKeyString(privateKey);
    nabto_device_string_free(privateKey);
    nabto_device_free(device);

    try {
        std::ofstream key(keyFileName);
        key << privateKeyString;
        return true;
    } catch (...) {
        return false;
    }
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
