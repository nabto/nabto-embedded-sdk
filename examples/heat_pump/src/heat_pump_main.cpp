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

#if defined(_WIN32)
#include <direct.h>
#endif

#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>

#ifdef WIN32
static std::string homeDirEnvVariable = "APPDATA";
static std::string nabtoFolder = "nabto";
#define NEWLINE "\r\n"
#else
static std::string homeDirEnvVariable = "HOME";
static std::string nabtoFolder = ".nabto";
#define NEWLINE "\n"
#endif

/**
 * The first time the heatpump is started init is called and writes a
 * configuration file. The configuration file is used in subsequent
 * runs of the heatpump.
 */


NabtoDevice* device = NULL;

void signal_handler(int s){
    printf("Caught signal %d, stopping the device" NEWLINE,s);
    nabto_device_stop(device);
}

bool makeDirectory(const std::string& directory)
{
#if defined(_WIN32)
    _mkdir(directory.c_str());
#else 
    mkdir(directory.c_str(), 0777);
#endif
    return true;
}

bool makeDirectories(const std::string& in)
{
    std::string homeDir;
    if (in.empty()) {
        char* tmp = getenv(homeDirEnvVariable.c_str());
        if (tmp == NULL) {
            return false;
        }
        std::string homeEnv = std::string(tmp);
        makeDirectory(homeEnv + "/" + nabtoFolder);
        makeDirectory(homeEnv + "/" + nabtoFolder + "/edge");
        homeDir = homeEnv + "/" + nabtoFolder + "/edge";
    } else {
        homeDir = in;
        makeDirectory(homeDir);
    }

    makeDirectory(homeDir+"/config");
    makeDirectory(homeDir+"/state");
    makeDirectory(homeDir+"/keys");
    return true;
}


bool run_heat_pump(const std::string& homedir, const std::string& logLevel, bool randomPorts);

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
        ("H,home-dir", "Home directory for the device. The default Home dir on unix is $HOME/.nabto/edge. On Windows the default home directory is %APP_DATA%/nabto/edge. The aplication uses the following files $homedir/keys/device.key, $homedir/config/device.json, $homedir/state/heat_pump_device_iam_state.json, $homedir/state/heat_pump_device_state.json", cxxopts::value<std::string>())
        ("log-level", "Log level to log (error|info|trace|debug)", cxxopts::value<std::string>()->default_value("error"))
        ("random-ports", "Use random ports such that several devices can be running at the same time. The device can still be discovered locally.")
        ("init", "Reset pump state to factory defaults and remove all paired users.")
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

        if (result.count("home-dir")) {
            makeDirectories(result["home-dir"].as<std::string>());
        } else {
            makeDirectories("");
        }

        std::string homedir;
        if (result.count("home-dir")) {
            homedir = result["home-dir"].as<std::string>();
        } else {
            const char* tmp = getenv(homeDirEnvVariable.c_str());
            if (!tmp) {
                std::cerr << "The system does not have a variable set for the home dir" << std::endl;
                homedir = ".";
            } else {
                homedir = std::string(tmp) + "/" + nabtoFolder + "/edge";
            }
        }

        if (result.count("init")) {
            std::string iamStateFile = homedir + "/state/heat_pump_device_iam_state.json";
            std::string hpStateFile = homedir + "/state/heat_pump_device_state.json";

            nabto::examples::heat_pump::create_default_iam_state(iamStateFile.c_str());
            nabto::examples::heat_pump::create_default_heat_pump_state(hpStateFile.c_str());
            std::cout << "Removed paired users and the heatpump state" << std::endl;
            return 0;
        }

        std::string logLevel = result["log-level"].as<std::string>();
        bool randomPorts = (result.count("random-ports") > 0);
        if (!run_heat_pump(homedir, logLevel, randomPorts)) {
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

bool run_heat_pump(const std::string& homedir, const std::string& logLevel, bool randomPorts)
{
    std::string configFile = homedir + "/config/device.json";
    std::string deviceKeyFile = homedir + "/keys/device.key";
    std::string iamStateFile = homedir + "/state/heat_pump_device_iam_state.json";
    std::string hpStateFile = homedir + "/state/heat_pump_device_state.json";

    nabto::examples::common::DeviceConfig dc(configFile);
    if (!dc.load()) {
        print_missing_device_config_help(configFile);
        return false;
    }

    if (!dc.isValid()) {
        print_invalid_device_config_help(configFile);
        return false;
    }

    device = nabto_device_new();
    if (device == NULL) {
        std::cerr << "Device New Failed" << std::endl;
        return false;
    }

    if (randomPorts) {
        nabto_device_set_local_port(device, 0);
        nabto_device_set_p2p_port(device, 0);
    }

    if (!load_or_create_private_key(device, deviceKeyFile.c_str(), NULL)) {
        std::cerr << "Could not load or create the private key" << std::endl;
        return false;
    }

    {

        nabto::examples::heat_pump::HeatPump hp(device, dc, iamStateFile, hpStateFile);
        hp.setLogLevel(logLevel);
        if (!hp.init()) {
            std::cerr << "Failed to init heat pump" << std::endl;
            return false;
        }
        hp.printHeatpumpInfo();


        // Wait for the user to press Ctrl-C

        signal(SIGINT, &signal_handler);

        // todo wait for the device to stop.
        {
            NabtoDeviceListener* listener = nabto_device_listener_new(device);
            NabtoDeviceFuture* future = nabto_device_future_new(device);
            nabto_device_device_events_init_listener(device, listener);
            NabtoDeviceEvent event;
            while(true) {
                nabto_device_listener_device_event(listener, future, &event);
                NabtoDeviceError ec = nabto_device_future_wait(future);
                if (ec != NABTO_DEVICE_EC_OK) {
                    break;
                }
                if (event == NABTO_DEVICE_EVENT_CLOSED) {
                    break;
                }
            }
            nabto_device_future_free(future);
            nabto_device_listener_free(listener);
        }
        NabtoDeviceFuture* fut = nabto_device_future_new(device);
        nabto_device_close(device, fut);
        nabto_device_future_wait(fut);
        nabto_device_future_free(fut);
    }
    nabto_device_stop(device);
    nabto_device_free(device);
    return true;
}
