#pragma once

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "tcptunnel_persisting.hpp"

#include <examples/common/stdout_connection_event_handler.hpp>
#include <examples/common/stdout_device_event_handler.hpp>
#include <examples/common/device_config.hpp>

#include <nlohmann/json.hpp>

#include <iostream>

namespace nabto {
namespace examples {
namespace tcptunnel {

class TcpTunnel {
 public:
    TcpTunnel(NabtoDevice* device, const std::string& privateKey, const std::string& policiesFile, nabto::examples::common::DeviceConfig& dc, TcpTunnelPersisting& state)
        : device_(device),
          privateKey_(privateKey),
          policiesFile_(policiesFile),
          deviceConfig_(dc),
          state_(state),
          fingerprintIAM_(device, state)
    {
        stdoutConnectionEventHandler_ = nabto::examples::common::StdoutConnectionEventHandler::create(device);
        stdoutDeviceEventHandler_ = nabto::examples::common::StdoutDeviceEventHandler::create(device);
    }

    ~TcpTunnel()
    {

    }

    bool init()
    {
        if (!initDevice()) {
            return false;
        }
        if (!loadIamConfig()) {
            return false;
        }
        return initAccessControl();
    }

    void setLogLevel(const std::string& logLevel)
    {
        NabtoDeviceError ec;
        ec = nabto_device_set_log_level(device_, logLevel.c_str());
        if (ec) {
            std::cerr << "Failed to set loglevel" << std::endl;
        }
    }

    void dumpIam();

    void printTunnelInfo()
    {
        char* fpTemp;
        nabto_device_get_device_fingerprint_hex(device_, &fpTemp);
        std::string fp(fpTemp);
        nabto_device_string_free(fpTemp);

        std::cout << "######## Nabto tcptunnel device ########" << std::endl;
        std::cout << "# Product ID:       " << deviceConfig_.getProductId() << std::endl;
        std::cout << "# Device ID:        " << deviceConfig_.getDeviceId() << std::endl;
        std::cout << "# Fingerprint:      " << fp << std::endl;
        std::cout << "# Paring Password:  " << state_.getPairingPassword() << std::endl;
        std::cout << "# Client Server Url " << deviceConfig_.getClientServerUrl() << std::endl;
        std::cout << "# Client Server Key " << deviceConfig_.getClientServerKey() << std::endl;
        std::cout << "# Version:          " << nabto_device_version() << std::endl;
        std::cout << "######## " << std::endl;
    }
 private:
    bool loadIamConfig();
    bool initAccessControl();


    bool initDevice();


    NabtoDevice* device_;
    std::string privateKey_;
    std::string policiesFile_;
    nabto::examples::common::DeviceConfig& deviceConfig_;
    TcpTunnelPersisting& state_;
    nabto::fingerprint_iam::FingerprintIAM fingerprintIAM_;


    std::unique_ptr<nabto::examples::common::StdoutConnectionEventHandler> stdoutConnectionEventHandler_;
    std::unique_ptr<nabto::examples::common::StdoutDeviceEventHandler> stdoutDeviceEventHandler_;
};

} } } // namespace
