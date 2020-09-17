#include "heat_pump.hpp"
#include "json_config.hpp"

#include <examples/common/device_config.hpp>
#include <apps/common/private_key.h>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <cxxopts.hpp>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#ifdef WIN32
static std::string homeEnv = "APP_DATA";
static std::string nabtoFolder = "nabto";
#else
static std::string homeEnv = "HOME";
static std::string nabtoFolder = ".nabto";
#endif

/**
 * The first time the heatpump is started init is called and writes a
 * configuration file. The configuration file is used in subsequent
 * runs of the heatpump.
 */

void my_handler(int s){
    printf("Caught signal %d\n",s);
}

bool run_heat_pump(const std::string& homedir, const std::string& logLevel, bool dumpIam, bool randomPorts);

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
        ("H,home-dir", "Home directory for the device. The default Home dir on unix is $HOME/.nabto/edge. On Windows the default home directory is %APP_DATA%/nabto/edge. The aplication uses the following files $homedir/keys/device.key, $homedir/config/device.json, $homedir/state/heat_pump_device_state.json", cxxopts::value<std::string>())
        ("log-level", "Log level to log (error|info|trace|debug)", cxxopts::value<std::string>()->default_value("error"))
        ("random-ports", "Use random ports such that several devices can be running at the same time")
        ("reset", "Reset pump state to factory defaults and remove all paired users.")
        ;

    // TOOD create directory structure.

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

        std::string homedir;
        if (result.count("home-dir")) {
            homedir = result["home-dir"].as<std::string>();
        } else {
            const char* tmp = getenv(homeEnv.c_str());
            if (!tmp) {
                std::cerr << "The system does not have a variable set for the home dir" << std::endl;
                homedir = ".";
            } else {
                homedir = std::string(tmp) + "/" + nabtoFolder + "/edge";
            }
        }

        if (result.count("reset")) {
            std::string stateFile = homedir + "/state/heat_pump_device_state.json";
            json_config_clear(stateFile);
            std::cout << "Removed paired users and the heatpump state" << std::endl;
            return 0;
        }

        std::string logLevel = result["log-level"].as<std::string>();
        bool dumpIam = (result.count("dump-iam") > 0);
        bool randomPorts = (result.count("random-ports") > 0);
        if (!run_heat_pump(homedir, logLevel, dumpIam, randomPorts)) {
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

bool run_heat_pump(const std::string& homedir, const std::string& logLevel, bool dumpIam, bool randomPorts)
{
    std::string configFile = homedir + "/config/device.json";
    std::string deviceKeyFile = homedir + "/keys/device.key";
    std::string stateFile = homedir + "/state/heat_pump_device_state.json";

    nabto::examples::common::DeviceConfig dc(configFile);
    if (!dc.load()) {
        print_missing_device_config_help(configFile);
        return false;
    }

    if (!dc.isValid()) {
        print_invalid_device_config_help(configFile);
        return false;
    }

    NabtoDevice* device = nabto_device_new();
    if (device == NULL) {
        std::cerr << "Device New Failed" << std::endl;
        return false;
    }

    if (randomPorts) {
        nabto_device_set_local_port(device, 0);
        nabto_device_set_p2p_port(device, 0);
    }

    if (!load_or_create_private_key(device, deviceKeyFile.c_str(), NULL)) {
        return false;
    }

    {

        nabto::examples::heat_pump::HeatPump hp(device, dc, stateFile);
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
