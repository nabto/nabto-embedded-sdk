#pragma once

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "tcptunnel_coap.hpp"
#include "coap_request_handler.hpp"

#include <examples/common/stdout_connection_event_handler.hpp>
#include <examples/common/stdout_device_event_handler.hpp>

#include <nlohmann/json.hpp>

class TcpTunnel {
 public:
    TcpTunnel(NabtoDevice* device, nlohmann::json config, const std::string& configFile)
        : device_(device), config_(config), configFile_(configFile)
    {
        stdoutConnectionEventHandler_ = nabto::examples::common::StdoutConnectionEventHandler::create(device);
        stdoutDeviceEventHandler_ = nabto::examples::common::StdoutDeviceEventHandler::create(device);
    }

    ~TcpTunnel()
    {
    }
    void init() {
        tcptunnel_coap_init(device_, this);
    }

    void deinit() {
        tcptunnel_coap_deinit(this);
    }

    NabtoDevice* getDevice() {
        return device_;
    }

    std::string getPairingPassword() {
        return config_["PairingPassword"].get<std::string>();
    }

    std::unique_ptr<nabto::common::CoapRequestHandler> coapPostPairingPassword;
    std::unique_ptr<nabto::common::CoapRequestHandler> coapGetPairingState;
 private:
    NabtoDevice* device_;
    nlohmann::json config_;
    const std::string& configFile_;

    std::unique_ptr<nabto::examples::common::StdoutConnectionEventHandler> stdoutConnectionEventHandler_;
    std::unique_ptr<nabto::examples::common::StdoutDeviceEventHandler> stdoutDeviceEventHandler_;
};
