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
    TcpTunnel(NabtoDevice* device, const std::string& privateKey, const std::string& policiesFile, nabto::examples::common::DeviceConfig& dc, const std::string& stateFile)
        : device_(device),
          privateKey_(privateKey),
          policiesFile_(policiesFile),
          deviceConfig_(dc),
          fingerprintIAM_(device)
    {
        state_ = std::make_shared<TcpTunnelPersisting>(stateFile, fingerprintIAM_);
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
        if (!loadIamPolicies()) {
            return false;
        }
        if (!state_->load()) {
            return false;
        }
        if (!initAccessControl()) {
            return false;
        }
        fingerprintIAM_.setChangeListener(state_);
        return true;
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
        std::cout << "# Fingerprint:      " << getFingerprint() << std::endl;
        std::cout << "# Paring Password:  " << state_->getPairingPassword() << std::endl;
        std::cout << "# Client Server Url " << deviceConfig_.getClientServerUrl() << std::endl;
        std::cout << "# Client Server Key " << deviceConfig_.getClientServerKey() << std::endl;
        std::cout << "# Version:          " << nabto_device_version() << std::endl;
        std::cout << "# Pairing URL:      " << createPairingLink() << std::endl;
        std::cout << "######## " << std::endl;
    }
 private:
    bool loadIamPolicies();
    bool initAccessControl();

    std::string getFingerprint()
    {
        char* fpTemp;
        nabto_device_get_device_fingerprint_hex(device_, &fpTemp);
        std::string fp(fpTemp);
        nabto_device_string_free(fpTemp);
        return fp;
    }

    std::string createPairingLink()
    {
        std::stringstream ss;
        ss << "https://tcptunnel.nabto.com/pairing"
           << "?ProductId=" << deviceConfig_.getProductId()
           << "&DeviceId=" << deviceConfig_.getDeviceId()
           << "&DeviceFingerprint=" << getFingerprint()
           << "&ClientServerUrl=" << deviceConfig_.getClientServerUrl()
           << "&ClientServerKey=" << deviceConfig_.getClientServerKey()
           << "&PairingPassword=" << state_->getPairingPassword();
        return ss.str();
    }

    bool initDevice();


    NabtoDevice* device_;
    std::string privateKey_;
    std::string policiesFile_;
    nabto::examples::common::DeviceConfig& deviceConfig_;
    std::shared_ptr<TcpTunnelPersisting> state_;
    nabto::fingerprint_iam::FingerprintIAM fingerprintIAM_;


    std::unique_ptr<nabto::examples::common::StdoutConnectionEventHandler> stdoutConnectionEventHandler_;
    std::unique_ptr<nabto::examples::common::StdoutDeviceEventHandler> stdoutDeviceEventHandler_;
};

} } } // namespace
