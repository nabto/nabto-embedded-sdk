
#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "test_device_application.hpp"

#include <util/tcp_echo_server.hpp>

#include "json_config.hpp"

#include <cxxopts.hpp>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>

#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;


void my_handler(int s){
    printf("Caught signal %d\n",s);
}

void run_device(const std::string& configFile, const std::string& logLevel)
{
    json config;
    if (!json_config_load(configFile, config)) {
        std::cerr << "The config file " << configFile << " does not exists, run with --init to create the config file" << std::endl;
        exit(-1);
    }

    std::string privateKey = config["PrivateKey"].get<std::string>();
    std::string productId = config["ProductId"].get<std::string>();
    std::string deviceId = config["DeviceId"].get<std::string>();
    std::string server = config["Server"].get<std::string>();

    nabto::test::TestDeviceApplication tda;

    tda.init(productId, deviceId, server, privateKey);

    std::cout << "Initialized device " << productId << "." << deviceId << " fingerprint: " << tda.getDeviceFingerprint() << std::endl;

    tda.start();

    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = my_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    pause();

    printf("closing\n");
}

bool init_test_device(const std::string& configFile, const std::string& productId, const std::string& deviceId, const std::string& server)
{
    if (json_config_exists(configFile)) {
        std::cerr << "The config already file exists, remove " << configFile << " and try again" << std::endl;
        exit(2);
    }
    json config;

    NabtoDevice* device = nabto_device_new();
    NabtoDeviceError ec;

    char* str;
    char* fp;
    ec = nabto_device_create_private_key(device, &str);
    std::string privateKey(str);
    if (ec) {
        std::cerr << "Error creating private key" << std::endl;
        return false;
    }
    ec = nabto_device_set_private_key(device, str);
    if (ec) {
        std::cerr << "Error setting private key" << std::endl;
        return false;
    }
    ec = nabto_device_get_device_fingerprint_hex(device, &fp);
    if (ec) {
        std::cerr << "Error getting Fingerprint" << std::endl;
        return false;
    }

    std::cout << "Created new private key with fingerprint: " << fp << std::endl;
    nabto_device_string_free(fp);
    nabto_device_string_free(str);

    config["PrivateKey"] = privateKey;
    config["ProductId"] = productId;
    config["DeviceId"] = deviceId;
    config["Server"] = server;

    json_config_save(configFile, config);

    nabto_device_stop(device);
    nabto_device_free(device);

    return true;
}

int main(int argc, char** argv)
{
    cxxopts::Options options("Test Device", "Nabto Test Device.");

    options.add_options("General")
        ("h,help", "Show help")
        ("i,init", "Write configuration to the config file and create a a private key")
        ("c,config", "Config file to write to", cxxopts::value<std::string>()->default_value("test_device.json"))
        ("log-level", "Log level to log (error|info|trace|debug)", cxxopts::value<std::string>()->default_value("info"));

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
            if (!init_test_device(configFile, productId, deviceId, server)) {
                std::cerr << "Initialization failed" << std::endl;
            }
        } else {
            std::string configFile = result["config"].as<std::string>();
            std::string logLevel = result["log-level"].as<std::string>();
            run_device(configFile, logLevel);
        }
    } catch (const cxxopts::OptionException& e) {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        exit(-1);
    } catch (const std::domain_error& e) {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        exit(-1);
    } catch (...) {
        std::cout << options.help() << std::endl;
        exit(-1);
    }
}
