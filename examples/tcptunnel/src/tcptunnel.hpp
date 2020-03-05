#pragma once

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "tcptunnel_persisting.hpp"
#include "tcptunnel_default_policies.hpp"

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
    TcpTunnel(NabtoDevice* device, const std::string& privateKey, const std::string& policiesFile, nabto::examples::common::DeviceConfig& dc, const std::string& stateFile, std::vector<TcpTunnelService> tcpTunnelServices)
        : device_(device),
          privateKey_(privateKey),
          policiesFile_(policiesFile),
          deviceConfig_(dc),
          fingerprintIAM_(device),
          tcpTunnelServices_(tcpTunnelServices)
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
        if (!initTcpServices()) {
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

    // print cell
    std::string pc(const std::string& str) {
        size_t width = 16;
        // truncate the string so it is never too long
        std::string tc = str.substr(0, width);

        return tc + std::string(width - tc.size(), ' ') + " ";
    }

    void printTunnelInfo()
    {
        char* fpTemp;
        nabto_device_get_device_fingerprint_full_hex(device_, &fpTemp);
        std::string fp(fpTemp);
        nabto_device_string_free(fpTemp);

        std::cout << "######## Nabto tcptunnel device ########" << std::endl;
        std::cout << "# Product ID:       " << deviceConfig_.getProductId() << std::endl;
        std::cout << "# Device ID:        " << deviceConfig_.getDeviceId() << std::endl;
        std::cout << "# Fingerprint:      " << getFingerprint() << std::endl;
        std::cout << "# Paring Password:  " << state_->getPairingPassword() << std::endl;
        std::cout << "# Client Server Url " << deviceConfig_.getClientServerUrl() << std::endl;
        std::cout << "# Client Server Key " << deviceConfig_.getClientServerKey() << std::endl;
        std::cout << "# Pairing SCT       " << state_->getPairingServerConnectToken() << std::endl;
        std::cout << "# Version:          " << nabto_device_version() << std::endl;
        std::cout << "# Pairing URL:      " << createPairingLink() << std::endl;
        std::cout << "# Configured TCP Services:" << std::endl;
        std::cout << "# "<< pc("Id") << pc("Type") << pc("Host") << pc("Port") << std::endl;
        for (auto s : tcpTunnelServices_) {
            std::cout << "# " << pc(s.id_) << pc(s.type_) << pc(s.host_) << pc(std::to_string(s.port_)) << std::endl;
        }
        std::cout << "######## " << std::endl;
    }
 private:
    bool loadIamPolicies();
    bool initAccessControl();
    bool initTcpServices();

    std::string getFingerprint()
    {
        char* fpTemp;
        nabto_device_get_device_fingerprint_full_hex(device_, &fpTemp);
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
           << "&PairingPassword=" << state_->getPairingPassword()
           << "&ClientServerConnectToken=" << state_->getPairingServerConnectToken();
        return ss.str();
    }

    bool initDevice();


    NabtoDevice* device_;
    std::string privateKey_;
    std::string policiesFile_;
    nabto::examples::common::DeviceConfig& deviceConfig_;
    std::shared_ptr<TcpTunnelPersisting> state_;
    nabto::fingerprint_iam::FingerprintIAM fingerprintIAM_;
    std::vector<TcpTunnelService> tcpTunnelServices_;


    std::unique_ptr<nabto::examples::common::StdoutConnectionEventHandler> stdoutConnectionEventHandler_;
    std::unique_ptr<nabto::examples::common::StdoutDeviceEventHandler> stdoutDeviceEventHandler_;
};

} } } // namespace
