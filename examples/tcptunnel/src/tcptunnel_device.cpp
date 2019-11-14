#include "tcptunnel.hpp"
#include "json_config.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <cxxopts.hpp>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <random>

static bool init_tcptunnel(const std::string& configFile, const std::string& productId, const std::string& deviceId, const std::string& server);
static bool run_tcptunnel(const std::string& configFile, const std::string& logLevel);

static std::string randomString(size_t n);

void my_handler(int s){
}

int main(int argc, char** argv)
{
    cxxopts::Options options("TCP Tunnel", "Nabto tcp tunnel example.");

    options.add_options("General")
        ("h,help", "Show help")
        ("version", "Show version")
        ("i,init", "Initialize configuration file")
        ("c,config", "Configuration file", cxxopts::value<std::string>()->default_value("tcptunnel_device.json"))
        ("log-level", "Log level to log (error|info|trace|debug)", cxxopts::value<std::string>()->default_value("error"));
     options.add_options("Init Parameters")
        ("p,product", "Product id", cxxopts::value<std::string>())
        ("d,device", "Device id", cxxopts::value<std::string>())
        ("s,server", "hostname of the server", cxxopts::value<std::string>());
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

        if (result.count("init") > 0) {
            std::string configFile = result["config"].as<std::string>();
            std::string productId = result["product"].as<std::string>();
            std::string deviceId = result["device"].as<std::string>();
            std::string server = result["server"].as<std::string>();
            if (!init_tcptunnel(configFile, productId, deviceId, server)) {
                std::cerr << "Initialization failed" << std::endl;
                return 2;
            }
        } else {
            std::string configFile = result["config"].as<std::string>();
            std::string logLevel = result["log-level"].as<std::string>();
            if (!run_tcptunnel(configFile, logLevel)) {
                std::cerr << "Failed to run TCP tunnel" << std::endl;
                return 3;
            }
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
const json defaultTcptunnelIam = R"(
{
  "DefaultRole": "Unpaired",
  "Policies": {
    "PasswordPairing": {
      "Statements": [
        {
          "Actions": [
            "Pairing:Password"
          ],
          "Allow": true
        }
      ],
      "Version": 1
    },
    "TunnelAll": {
      "Statements": [
        {
          "Actions": [ "TcpTunnel:Create" ],
          "Allow": true
        }
      ],
      "Version": 1
    },
    "P2P": {
      "Statements": [
        {
          "Actions": [ "P2P:Stun", "P2P:Rendezvous" ],
          "Allow": true
        }
      ],
      "Version": 1
    },
    "Paired": {
      "Statements": [
        {
          "Actions": [ "Pairing:IsPaired" ],
          "Allow": true
        }
      ],
      "Version": 1
    }
  },
  "Roles": {
    "Unpaired": [
      "PasswordPairing", "P2P"
    ],
    "Tunnelling": [
      "TunnelAll", "P2P"
    ],
    "Paired": [
      "Paired"
    ]
  },
  "Users": {
    "DefaultUser": {
      "Roles": [ "Tunnelling", "Paired" ],
      "Fingerprints": []
    }
  }
}
)"_json;

bool init_tcptunnel(const std::string& configFile, const std::string& productId, const std::string& deviceId, const std::string& server)
{
    if (json_config_exists(configFile)) {
        std::cerr << "The config already file exists, remove " << configFile << " and try again" << std::endl;
        return false;
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

    config["PairingPassword"] = randomString(16);

    std::vector<uint8_t> iamCbor = json::to_cbor(defaultTcptunnelIam);
    std::cout << "iam size " << iamCbor.size() << std::endl;

    // test the iam config
    ec = nabto_device_iam_load(device, iamCbor.data(), iamCbor.size());
    if (ec) {
        std::cerr << "Error loading default iam " << nabto_device_error_get_message(ec) << std::endl;
        return false;
    }

    config["Iam"] = defaultTcptunnelIam;

    json_config_save(configFile, config);

    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_close(device, fut);
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
    nabto_device_stop(device);
    nabto_device_free(device);

    return true;
}

bool run_tcptunnel(const std::string& configFile, const std::string& logLevel)
{
    NabtoDeviceError ec;
    json config;
    if (!json_config_load(configFile, config)) {
        std::cerr << "The config file " << configFile << " does not exists, run with --init to create the config file" << std::endl;
        return false;
    }

    NabtoDevice* device = nabto_device_new();
    if (!device) {
        std::cerr << "Could not create device" << std::endl;
        return false;
    }

    auto productId = config["ProductId"].get<std::string>();
    auto deviceId  = config["DeviceId"].get<std::string>();
    auto server = config["Server"].get<std::string>();
    auto privateKey = config["PrivateKey"].get<std::string>();
    auto pairingPassword = config["PairingPassword"].get<std::string>();
    auto iam = config["Iam"];


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
    std::vector<uint8_t> iamCbor = json::to_cbor(iam);

    ec = nabto_device_iam_load(device, iamCbor.data(), iamCbor.size());
    if (ec) {
        std::cerr << "failed to load iam" << std::endl;
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
    std::cout << "# Paring Password: " << pairingPassword << std::endl;
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

std::string randomString(size_t n) {
    const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, characters.size() - 1);

    std::string randomString;

    for (std::size_t i = 0; i < n; ++i)
    {
        randomString += characters[distribution(generator)];
    }

    return randomString;
}
