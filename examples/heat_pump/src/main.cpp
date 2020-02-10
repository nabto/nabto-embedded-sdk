#include "heat_pump.hpp"
#include "json_config.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <modules/iam_cpp/iam.hpp>
#include <modules/iam_cpp/iam_builder.hpp>


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

bool init_heat_pump(const std::string& configFile, const std::string& productId, const std::string& deviceId, const std::string& server, const std::string& clientServerUrl, const std::string& clientServerKey);
bool run_heat_pump(const std::string& configFile, const std::string& logLevel);
bool reset_iam(const std::string& configFile);

static void loadStaticIamPolicy(nabto::FingerprintIAM& iam);

int main(int argc, char** argv) {
    cxxopts::Options options("Heat pump", "Nabto heat pump example.");

    options.add_options("General")
        ("h,help", "Show help")
        ("version", "Show version")
        ("i,init", "Initialize configuration file")
        ("reset-iam", "Remove paired users and custom iam changed.")
        ("c,config", "Configuration file", cxxopts::value<std::string>()->default_value("heat_pump_device.json"))
        ("log-level", "Log level to log (error|info|trace|debug)", cxxopts::value<std::string>()->default_value("info"))
        ("log-file", "File to log to", cxxopts::value<std::string>()->default_value("heat_pump_device_log.txt"));

    options.add_options("Init Parameters")
        ("p,product", "Product id", cxxopts::value<std::string>())
        ("d,device", "Device id", cxxopts::value<std::string>())
        ("s,server", "hostname of the server", cxxopts::value<std::string>())
        ("client-server-url", "the server the client can use to connect to the device.", cxxopts::value<std::string>())
        ("client-server-key", "the server key the client can use to connect to the device.", cxxopts::value<std::string>())
        ;

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
            std::string clientServerUrl = result["client-server-url"].as<std::string>();
            std::string clientServerKey = result["client-server-key"].as<std::string>();
            if (!init_heat_pump(configFile, productId, deviceId, server, clientServerUrl, clientServerKey)) {
                std::cerr << "Initialization failed" << std::endl;
                return 2;
            }
        } else if (result.count("reset-iam") > 0) {
            std::string configFile = result["config"].as<std::string>();
            if (!reset_iam(configFile)) {
                std::cerr << "Reset of IAM failed" << std::endl;
                return 4;
            }
        } else {
            std::string configFile = result["config"].as<std::string>();
            std::string logLevel = result["log-level"].as<std::string>();
            if (!run_heat_pump(configFile, logLevel)) {
                std::cerr << "Failed to run heatpump" << std::endl;
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

bool reset_iam(const std::string& configFile) {
    json config;
    if (!json_config_load(configFile, config)) {
        std::cerr << "The config file " << configFile << " does not exists, run with --init to create the config file" << std::endl;
        return false;
    }
    nabto::HeatPumpPersisting hpp(configFile);
    if (!hpp.load()) {
        return false;
    }
    hpp.deleteAllUsers();
    hpp.save();
    return true;
}

bool init_heat_pump(const std::string& configFile, const std::string& productId, const std::string& deviceId, const std::string& server, const std::string& clientServerUrl, const std::string& clientServerKey)
{
    if (json_config_exists(configFile)) {
        std::cerr << "The config already file exists, remove " << configFile << " and try again" << std::endl;
        exit(2);
    }

    json config;

    NabtoDevice* device = nabto_device_new();
    if (device == NULL) {
        std::cerr << "Could not create device" << std::endl;
        return false;
    }
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

    nabto::HeatPumpPersisting hpp(configFile);

    hpp.setPrivateKey(privateKey);
    hpp.setProductId(productId);
    hpp.setDeviceId(deviceId);
    hpp.setServer(server);
    hpp.setClientServerUrl(clientServerUrl);
    hpp.setClientServerKey(clientServerKey);
    hpp.setHeatPumpMode("COOL");
    hpp.setHeatPumpPower(false);
    hpp.setHeatPumpTarget(22.3);
    hpp.save();

    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_close(device, fut);
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
    nabto_device_stop(device);
    nabto_device_free(device);

    return true;
}

bool run_heat_pump(const std::string& configFile, const std::string& logLevel)
{
    if (!json_config_exists(configFile)) {
        std::cerr << "The config does not exists, create it with --init first" << std::endl;
        exit(2);
    }

    NabtoDevice* device = nabto_device_new();
    if (device == NULL) {
        std::cerr << "Device New Failed" << std::endl;
        return false;
    }

    nabto::HeatPumpPersisting hpp(configFile);

    hpp.load();


    {
        nabto::FingerprintIAM iam(device, hpp);
        loadStaticIamPolicy(iam);

        HeatPump hp(device, iam, hpp);
        hp.initDevice();
        hp.init();
        hp.setLogLevel(logLevel);

        // Wait for the user to press Ctrl-C

        struct sigaction sigIntHandler;

        sigIntHandler.sa_handler = my_handler;
        sigemptyset(&sigIntHandler.sa_mask);
        sigIntHandler.sa_flags = 0;

        sigaction(SIGINT, &sigIntHandler, NULL);

        pause();

        hp.deinit();
        NabtoDeviceFuture* fut = nabto_device_future_new(device);
        nabto_device_close(device, fut);
        nabto_device_future_wait(fut);
        nabto_device_future_free(fut);
    }
    nabto_device_stop(device);
    nabto_device_free(device);
    return true;
}

void loadStaticIamPolicy(nabto::FingerprintIAM& iam)
{
    auto buttonPairingPolicy = nabto::iam::PolicyBuilder()
        .name("ButtonPairing")
        .addStatement(nabto::iam::StatementBuilder()
                      .allow()
                      .addAction("Pairing:Button")
                      .build())
        .build();

    auto readPolicy = nabto::iam::PolicyBuilder()
        .name("HeatPumpRead")
        .addStatement(nabto::iam::StatementBuilder()
                      .allow()
                      .addAction("HeatPump:Get")
                      .build())
        .build();

    auto writePolicy = nabto::iam::PolicyBuilder()
        .name("HeatPumpWrite")
        .addStatement(nabto::iam::StatementBuilder()
                      .allow()
                      .addAction("HeatPump:Set")
                      .addAction("IAM:AddUser")
                      .addAction("IAM:GetUser")
                      .addAction("IAM:ListUsers")
                      .addAction("IAM:AddRoleToUser")
                      .addAction("IAM:RemoveRoleFromUser")
                      .build())
        .build();

    auto modifyOwnUserPolicy = nabto::iam::PolicyBuilder()
        .name("ModifyOwnUser")
        .addStatement(nabto::iam::StatementBuilder()
                      .allow()
                      .addAction("IAM:GetUser")
                      .addAction("IAM:ListUsers")
                      .addAction("IAM:AddFingerprint")
                      .addAction("IAM:RemoveFingerprint")
                      .addAttributeEqualCondition("Connection:UserId", "IAM:UserId")
                      .build())
        .build();

    iam.addPolicy(buttonPairingPolicy);
    iam.addPolicy(readPolicy);
    iam.addPolicy(writePolicy);
    iam.addPolicy(modifyOwnUserPolicy);

    iam.addRole(nabto::RoleBuilder().name("Unpaired").addPolicy("ButtonPairing"));
    iam.addRole(nabto::RoleBuilder().name("Owner")
                .addPolicy("HeatPumpWrite")
                .addPolicy("HeatPumpRead"));
    iam.addRole(nabto::RoleBuilder().name("User")
                .addPolicy("HeatPumpRead")
                .addPolicy("HeatPumpWrite")
                .addPolicy("ModifyOwnUser"));
    iam.addRole(nabto::RoleBuilder().name("Guest")
                .addPolicy("HeatPumpRead"));

}
