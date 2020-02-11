#include "tcptunnel.hpp"
#include "json_config.hpp"

#include "tcptunnel_default_policies.hpp"
#include "tcptunnel_private_key.hpp"
#include "tcptunnel_persisting.hpp"

#include <examples/common/random_string.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <cxxopts.hpp>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <random>

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

static bool run_tcptunnel(const std::string& configFile, const std::string& policiesFile, const std::string& stateFile, const std::string& logLevel);

void print_missing_device_config_help(const std::string& filename)
{
    std::cout << "The device config is missing (" << filename << "). Provide a file named " << filename << " with the following format" << std::endl;
    std::cout << exampleDeviceConfig << std::endl;
}

void my_handler(int s){
}

int main(int argc, char** argv)
{
    cxxopts::Options options("TCP Tunnel", "Nabto tcp tunnel example.");

    options.add_options("General")
        ("h,help", "Show help")
        ("version", "Show version")

        ("config", "Configuration for the device", cxxopts::value<std::string>()->default_value("device_config.json"))
        ("policies", "Configuration file containing the policies if it does not exists it's created", cxxopts::value<std::string>()->default_value("tcptunnel_policies.json"))
        ("state", "File containing the state of the tcptunnel", cxxopts::value<std::string>()->default_value("tcptunnel_state.json"))

        ("log-level", "Log level to log (error|info|trace|debug)", cxxopts::value<std::string>()->default_value("error"));

    try {

        auto result = options.parse(argc, argv);

        if (result.count("help"))
        {
            std::cout << options.help() << std::endl;
            return 0;
        }

        if (result.count("version"))
        {
            std::cout << "nabto_embedded_sdk: " << nabto_device_version() << std::endl;
            return 0;
        }

        std::string configFile = result["config"].as<std::string>();
        std::string policiesFile = result["policies"].as<std::string>();
        std::string stateFile = result["state"].as<std::string>();
        std::string logLevel = result["log-level"].as<std::string>();
        if (!run_tcptunnel(configFile, policiesFile, stateFile, logLevel)) {
            std::cerr << "Failed to run TCP tunnel" << std::endl;
            return 3;
        }
    } catch (const cxxopts::OptionException& e) {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        return -1;
    } catch (const std::domain_error& e) {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        return -1;
    }
    return 0;
}

bool run_tcptunnel(const std::string& configFile, const std::string& policiesFile, const std::string& stateFile, const std::string& logLevel)
{
    nlohmann::json config;
    if (!json_config_load(configFile, config)) {
        print_missing_device_config_help(configFile);
        return false;
    }

    if (!json_config_exists(policiesFile)) {
        std::cout << "The policies file is not found, creating a new file with default policies" << std::endl;
        init_default_policies(policiesFile);
    }

    std::stringstream keyFileName;
    keyFileName << config["DeviceId"].get<std::string>() << "_" << config["ProductId"].get<std::string>() << ".key.json";

    std::string privateKey;
    if (!load_private_key(keyFileName.str(), privateKey)) {
        return false;
    }

    nabto::examples::tcptunnel::TcpTunnelPersisting ttp(stateFile);
    ttp.load();

    NabtoDeviceError ec;
    NabtoDevice* device = nabto_device_new();
    if (!device) {
        std::cerr << "Could not create device" << std::endl;
        return false;
    }

    auto productId = config["ProductId"].get<std::string>();
    auto deviceId  = config["DeviceId"].get<std::string>();
    auto server = config["Server"].get<std::string>();

    ec = nabto_device_set_product_id(device, productId.c_str());
    if (ec) {
        std::cerr << "Could not set product id" << std::endl;
        return false;
    }
    ec = nabto_device_set_device_id(device, deviceId.c_str());
    if (ec) {
        std::cerr << "Could not set device id" << std::endl;
        return false;
    }
    ec = nabto_device_set_server_url(device, server.c_str());
    if (ec) {
        std::cerr << "Could not set server url" << std::endl;
        return false;
    }
    ec = nabto_device_set_private_key(device, privateKey.c_str());
    if (ec) {
        std::cerr << "Could not set private key" << std::endl;
        return false;
    }

    ec = nabto_device_enable_mdns(device);
    if (ec) {
        std::cerr << "Failed to enable mdns" << std::endl;
        return false;
    }
    ec = nabto_device_enable_tcp_tunnelling(device);
    if (ec) {
        std::cerr << "Failed to enable tcp tunnelling" << std::endl;
        return false;
    }
    ec = nabto_device_set_log_level(device, logLevel.c_str());
    if (ec) {
        std::cerr << "Failed to set loglevel" << std::endl;
        return false;
    }
    ec = nabto_device_set_log_std_out_callback(device);
    if (ec) {
        std::cerr << "Failed to enable stdour logging" << std::endl;
        return false;
    }

    try {
        auto serverPort = config["ServerPort"].get<uint16_t>();
        ec = nabto_device_set_server_port(device, serverPort);
        if (ec) {
            std::cerr << "Failed to set server port" << std::endl;
            return false;
        }
    } catch (std::exception& e) {
        // ServerPort not in config, just ignore and use default port
    }

    // run application
    ec = nabto_device_start(device);
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_free(device);
        std::cerr << "Failed to start device" << std::endl;
        return false;
    }

    char* fpTemp;
    ec = nabto_device_get_device_fingerprint_hex(device, &fpTemp);
    if (ec) {
        std::cerr << "Could not get fingerprint of the device" << std::endl;
        return false;
    }
    std::string fp(fpTemp);
    nabto_device_string_free(fpTemp);

    std::cout << "######## Nabto tcptunnel device ########" << std::endl;
    std::cout << "# Product ID:      " << productId << std::endl;
    std::cout << "# Device ID:       " << deviceId << std::endl;
    std::cout << "# Fingerprint:     " << std::string(fp) << std::endl;
    std::cout << "# Paring Password: " << ttp.getPairingPassword() << std::endl;
    std::cout << "# Version:         " << nabto_device_version() << std::endl;
    std::cout << "######## " << std::endl;

    {
        TcpTunnel tcpTunnel(device, config, configFile);
        tcpTunnel.init();

        // Wait for the user to press Ctrl-C

        struct sigaction sigIntHandler;

        sigIntHandler.sa_handler = my_handler;
        sigemptyset(&sigIntHandler.sa_mask);
        sigIntHandler.sa_flags = 0;

        sigaction(SIGINT, &sigIntHandler, NULL);

        pause();

        NabtoDeviceFuture* fut = nabto_device_future_new(device);
        nabto_device_close(device, fut);
        nabto_device_future_wait(fut);
        nabto_device_future_free(fut);
        tcpTunnel.deinit();

        nabto_device_stop(device);
    }

    nabto_device_free(device);
    return true;
}
