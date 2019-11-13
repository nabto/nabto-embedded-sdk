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
    {
        connectionEventListener_ = nabto_device_listener_new(device);
        deviceEventListener_ = nabto_device_listener_new(device);

        iamChangedFuture_ = nabto_device_future_new(device);
        connectionEventFuture_ = nabto_device_future_new(device);
        deviceEventFuture_ = nabto_device_future_new(device);
    }

    ~TcpTunnel() {

        nabto_device_listener_free(connectionEventListener_);
        nabto_device_listener_free(deviceEventListener_);

        nabto_device_future_free(connectionEventFuture_);
        nabto_device_future_free(deviceEventFuture_);
        nabto_device_future_free(iamChangedFuture_);
    }
    void init() {
        tcptunnel_coap_init(device_, this);
        listenForIamChanges();
        listenForConnectionEvents();
        listenForDeviceEvents();
    }

    void deinit() {
        tcptunnel_coap_deinit(this);
        if (connectionEventListener_) {
            nabto_device_listener_stop(connectionEventListener_);
        }
        if (deviceEventListener_) {
            nabto_device_listener_stop(deviceEventListener_);
        }
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
    static void iamChanged(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData);
    void listenForIamChanges();

    static void connectionEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData);
    void listenForConnectionEvents();
    void startWaitEvent();

    static void deviceEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData);
    void listenForDeviceEvents();
    void startWaitDevEvent();

    void saveConfig();

    NabtoDevice* device_;
    json config_;
    const std::string& configFile_;
    uint64_t currentIamVersion_;

    NabtoDeviceFuture* connectionEventFuture_;
    NabtoDeviceListener* connectionEventListener_;
    NabtoDeviceConnectionRef connectionRef_;
    NabtoDeviceConnectionEvent connectionEvent_;

    NabtoDeviceFuture* deviceEventFuture_;
    NabtoDeviceListener* deviceEventListener_;
    NabtoDeviceEvent deviceEvent_;

    NabtoDeviceFuture* iamChangedFuture_;
};
