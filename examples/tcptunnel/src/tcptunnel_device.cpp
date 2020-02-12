#include "tcptunnel.hpp"
#include "json_config.hpp"

#include "tcptunnel_default_policies.hpp"
#include "tcptunnel_persisting.hpp"

#include <examples/common/random_string.hpp>
#include <examples/common/device_config.hpp>
#include <examples/common/private_key.hpp>

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

static bool run_tcptunnel(const std::string& configFile, const std::string& policiesFile, const std::string& stateFile, const std::string& logLevel, bool dumpIam);

void print_missing_device_config_help(const std::string& filename)
{
    std::cout << "The device config is missing (" << filename << "). Provide a file named " << filename << " with the following format" << std::endl;
    std::cout << exampleDeviceConfig << std::endl;
}

void print_invalid_device_config_help(const std::string& filename)
{
    std::cout << "The device config is invalid (" << filename << "). Provide a file named " << filename << " with the following format" << std::endl;
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

        ("log-level", "Log level to log (error|info|trace|debug)", cxxopts::value<std::string>()->default_value("error"))
        ("dump-iam", "Print the iam configuration when the device is started, Policies, Roles Users");

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
        bool dumpIam = (result.count("dump-iam") > 0);
        if (!run_tcptunnel(configFile, policiesFile, stateFile, logLevel, dumpIam)) {
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

bool run_tcptunnel(const std::string& configFile, const std::string& policiesFile, const std::string& stateFile, const std::string& logLevel, bool dumpIam)
{
    nabto::examples::common::DeviceConfig dc(configFile);
    if (!dc.load()) {
        print_missing_device_config_help(configFile);
        return false;
    }

    if (!dc.isValid()) {
        print_invalid_device_config_help(configFile);
    }

    if (!json_config_exists(policiesFile)) {
        std::cout << "The policies file is not found, creating a new file with default policies" << std::endl;
        init_default_policies(policiesFile);
    }

    std::stringstream keyFileName;
    keyFileName << dc.getProductId() << "_" << dc.getDeviceId() << ".key.json";

    std::string privateKey;
    if (!load_private_key(keyFileName.str(), privateKey)) {
        return false;
    }

    nabto::examples::tcptunnel::TcpTunnelPersisting ttp(stateFile);
    ttp.load();

    NabtoDevice* device = nabto_device_new();
    if (!device) {
        std::cerr << "Could not create device" << std::endl;
        return false;
    }

    {
        nabto::examples::tcptunnel::TcpTunnel tcpTunnel(device, privateKey, policiesFile, dc, ttp);
        tcpTunnel.init();

        if (dumpIam) {
            tcpTunnel.dumpIam();
        }

        tcpTunnel.printTunnelInfo();
        tcpTunnel.setLogLevel(logLevel);

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
    }
    nabto_device_stop(device);

    nabto_device_free(device);
    return true;
}
