#include "heatpump_iam_policies.hpp"
#include "heatpump_config.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdio.h>
#include <stdlib.h>

#include <cxxopts.hpp>

void print_help(const char* message);
bool parse_args(int argc, const char** argv, NabtoDevice* device);
bool initialize_application(int argc, const char** argv, NabtoDevice* device);

// void print_help(const char* message)
// {
//     if (message) {
//         printf("%s", message);
//         printf(NEWLINE);
//     }
//     printf("test_device version %s" NEWLINE, nabto_device_version());
//     printf(" USAGE test_device -p <productId> -d <deviceId> -k <keyfile> --hostname <hostname>" NEWLINE);
// }

// bool initialize_application(int argc, const char** argv, NabtoDevice* device)
// {
//     if (!heatpump_config_has_private_key()) {
//         printf("No private key exists creating a new private key\n");
//         if (!heatpump_config_create_new_private_key(device)) {
//             printf("Could not create a new private key\n");
//             return false;
//         }
//     }

//     if (!heatpump_config_read_private_key(device)) {
//         printf("Could not read private key from file\n");
//         return false;
//     }

//     NabtoDeviceError ec = nabto_device_start(device);
//     if (ec != NABTO_DEVICE_EC_OK) {
//         printf("Failed to start device\n");
//         return false;
//     }

//     return true;
// }

bool validate_config(const json& config) {
    try {
        config["ProductId"].get<std::string>();
        config["DeviceId"].get<std::string>();
        config["Server"].get<std::string>();
        config["PrivateKey"].get<std::string>();
        config["Iam"]["Users"];
        config["Iam"]["Roles"];
        config["Iam"]["Policies"];
    } catch (std::exception& e) {
        return false;
    }
    return true;

}

NabtoDeviceError load_policy(NabtoDevice* device, const std::string& name, json policy)
{
    auto cbor = json::to_cbor(policy);
    return nabto_device_iam_policy_create(device, name.c_str(), cbor.data(), cbor.size());
}

bool init_heatpump(const std::string& configFile, const std::string& productId, const std::string& deviceId, const std::string& server)
{
    if (heatpump_config_exists(configFile)) {
        std::cerr << "The config already file exists, remove " << configFile << " and try again" << std::endl;
        exit(2);
    }

    json config;

    NabtoDevice* device = nabto_device_new();

    char* privateKey = nabto_device_experimental_util_create_private_key(device);
    config["PrivateKey"] = std::string(privateKey);
    config["ProductId"] = productId;
    config["DeviceId"] = deviceId;
    config["Server"] = server;

    if (nabto_device_iam_users_create(device, "Unpaired") != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (nabto_device_iam_roles_create(device, "FirstUser") != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (nabto_device_iam_users_add_role(device, "Unpaired", "FirstUser") != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (load_policy(device, "HeatPumpRead", HeatPumpRead) != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (load_policy(device, "HeatPumpWrite", HeatPumpWrite) != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (load_policy(device, "FirstUserCanPair", FirstUserCanPair) != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (nabto_device_iam_roles_add_policy(device, "FirstUser", "FirstUserCanPair") != NABTO_DEVICE_EC_OK) {
        return false;
    }
    uint64_t version;
    size_t used;
    if (nabto_device_iam_dump(device, &version, NULL, 0, &used) != NABTO_DEVICE_EC_OUT_OF_MEMORY) {
        return false;
    }

    std::vector<uint8_t> buffer(used);
    if(nabto_device_iam_dump(device, &version, buffer.data(), buffer.size(), &used) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    config["Iam"] = json::from_cbor(buffer);


    std::string tmpFile = "tmp.json";
    heatpump_save_config(configFile, tmpFile, config);

    nabto_device_free(device);

    return true;
}

void run_heatpump(const std::string& configFile)
{
    json config;
    if (!heatpump_load_config(configFile, config)) {
        std::cerr << "The config file " << configFile << " does not exists, run with --init to create the config file" << std::endl;
        exit(-1);
    }



    NabtoDevice* device = nabto_device_new();

    auto productId = config["ProductId"].get<std::string>();
    auto deviceId  = config["DeviceId"].get<std::string>();
    auto server = config["Server"].get<std::string>();
    auto privateKey = config["PrivateKey"].get<std::string>();
    auto iam = config["Iam"];



    nabto_device_set_product_id(device, productId.c_str());
    nabto_device_set_device_id(device, deviceId.c_str());
    nabto_device_set_server_url(device, server.c_str());
    nabto_device_set_private_key(device, privateKey.c_str());

    // run application

    printf("Press enter to stop\n");
    int c = 0;
    while (c != '\n') {
        c = getchar();
    }
    nabto_device_free(device);

}

int main(int argc, char** argv) {
    printf("Initializing Heatpump\n");

    cxxopts::Options options("Heatpump", "Nabto Heatpump example.");

    //options.show_positional_help();

    options.add_options("General")
        ("h,help", "Show help")
        ("i,init", "Initialize configuration file")
        ("c,config", "Configuration file", cxxopts::value<std::string>()->default_value("heatpump.json"));

    options.add_options("Init Parameters")
        ("p,product", "Product id", cxxopts::value<std::string>())
        ("d,device", "Device id", cxxopts::value<std::string>())
        ("s,server", "hostname of the server", cxxopts::value<std::string>());

    try {

        auto result = options.parse(argc, argv);

        if (result.count("help"))
        {
            std::cout << options.help() << std::endl;
            exit(0);
        }

        if (result.count("init") > 0) {
            std::string configFile = result["config"].as<std::string>();
            std::string productId = result["product"].as<std::string>();
            std::string deviceId = result["device"].as<std::string>();
            std::string server = result["server"].as<std::string>();
            if (!init_heatpump(configFile, productId, deviceId, server)) {
                std::cerr << "Initialization failed" << std::endl;
            }
        } else {
            std::string configFile = result["config"].as<std::string>();
            run_heatpump(configFile);
        }
    } catch (const cxxopts::OptionException& e) {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        exit(-1);
    } catch (const std::domain_error& e) {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        exit(-1);
    }
    return 0;
}
