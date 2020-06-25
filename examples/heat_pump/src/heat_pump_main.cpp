#include "heat_pump.hpp"
#include "json_config.hpp"

#include <examples/common/device_config.hpp>
#include <examples/common/private_key.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <cxxopts.hpp>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/**
 * The first time the heatpump is started init is called and writes a
 * configuration file. The configuration file is used in subsequent
 * runs of the heatpump.
 */

void my_handler(int s){
    printf("Caught signal %d\n",s);
}

bool run_heat_pump(const std::string& configFile, const std::string& stateFile, const std::string& logLevel, bool dumpIam);

void print_missing_device_config_help(const std::string& filename)
{
    std::cout << "The device config is missing (" << filename << "). Provide a file named " << filename << " with the following format" << std::endl;
    std::cout << nabto::examples::common::DeviceConfig::example() << std::endl;
}

void print_invalid_device_config_help(const std::string& filename)
{
    std::cout << "The device config is invalid (" << filename << "). Provide a file named " << filename << " with the following format" << std::endl;
    std::cout << nabto::examples::common::DeviceConfig::example() << std::endl;
}

int main(int argc, char** argv) {
    cxxopts::Options options("Heat pump", "Nabto heat pump example.");

    options.add_options("General")
        ("h,help", "Show help")
        ("version", "Show version")
        ("config", "Configuration for the device", cxxopts::value<std::string>()->default_value("device.json"))
        ("state", "File containing the state of the tcptunnel", cxxopts::value<std::string>()->default_value("heat_pump_state.json"))
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
        std::string stateFile = result["state"].as<std::string>();
        std::string logLevel = result["log-level"].as<std::string>();
        bool dumpIam = (result.count("dump-iam") > 0);
        if (!run_heat_pump(configFile, stateFile, logLevel, dumpIam)) {
            std::cerr << "Failed to run Heat Pump" << std::endl;
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

bool run_heat_pump(const std::string& configFile, const std::string& stateFile, const std::string& logLevel, bool dumpIam)
{
    nabto::examples::common::DeviceConfig dc(configFile);
    if (!dc.load()) {
        print_missing_device_config_help(configFile);
        return false;
    }

    if (!dc.isValid()) {
        print_invalid_device_config_help(configFile);
        return false;
    }

    std::stringstream keyFileName;
    keyFileName << dc.getProductId() << "_" << dc.getDeviceId() << ".key.json";

    std::string privateKey;
    if (!load_private_key(keyFileName.str(), privateKey)) {
        return false;
    }

    NabtoDevice* device = nabto_device_new();
    if (device == NULL) {
        std::cerr << "Device New Failed" << std::endl;
        return false;
    }

    {

        nabto::examples::heat_pump::HeatPump hp(device, privateKey, dc, stateFile);
        hp.setLogLevel(logLevel);
        hp.init();
        if (dumpIam) {
            hp.dumpIam();
        }
        hp.printHeatpumpInfo();


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
