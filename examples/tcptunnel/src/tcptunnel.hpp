#pragma once

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "tcptunnel_coap.hpp"
#include "coap_request_handler.hpp"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

class TcpTunnel {
 public:
    TcpTunnel(NabtoDevice* device, json config, const std::string& configFile)
        : device_(device), config_(config), configFile_(configFile)
    {}

    void init() {
        tcptunnel_coap_init(device_, this);
        listenForIamChanges();
        listenForConnectionEvents();
    }

    void deinit() {
        if (connectionEventHandler_) {
            nabto_device_event_handler_free(connectionEventHandler_);
            connectionEventHandler_ = NULL;
        }
    }

    NabtoDevice* getDevice() {
        return device_;
    }

    std::unique_ptr<nabto::common::CoapRequestHandler> coapPostPairingPassword;
 private:
    static void iamChanged(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData);
    void listenForIamChanges();
    static void connectionEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData);
    void listenForConnectionEvents();
    void startWaitEvent();
    void saveConfig();

    NabtoDevice* device_;
    json config_;
    const std::string& configFile_;
    uint64_t currentIamVersion_;

    NabtoDeviceEventHandler* connectionEventHandler_;
    NabtoDeviceConnectionRef connectionRef_;
    NabtoDeviceConnectionEvent connectionEvent_;
};
