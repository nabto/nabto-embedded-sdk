#ifndef _HEAT_PUMP_HPP_
#define _HEAT_PUMP_HPP_

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "heat_pump_persisting.hpp"
#include <modules/fingerprint_iam/fingerprint_iam.hpp>

#include <nlohmann/json.hpp>

#include <mutex>
#include <thread>
#include <sstream>

using json = nlohmann::json;


class HeatPump;

typedef std::function<void (NabtoDeviceCoapRequest* request, HeatPump* application)> CoapHandler;

class HeatPumpCoapRequestHandler {
 public:
    ~HeatPumpCoapRequestHandler() {
        nabto_device_listener_free(listener_);
        nabto_device_future_free(future_);
    }
    HeatPumpCoapRequestHandler(HeatPump* hp, NabtoDeviceCoapMethod methdod, const char** pathSegments, CoapHandler handler);

    void startListen();

    void stopListen() {
        nabto_device_listener_stop(listener_);
    }

    static void requestCallback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        HeatPumpCoapRequestHandler* handler = (HeatPumpCoapRequestHandler*)data;
        if (ec != NABTO_DEVICE_EC_OK) {
            return;
        }
        handler->handler_(handler->request_, handler->heatPump_);
        handler->startListen();
    }

    HeatPump* heatPump_;
    //  wait for a request
    NabtoDeviceFuture* future_;
    NabtoDeviceCoapRequest* request_;
    // on this listener
    NabtoDeviceListener* listener_;
    // invoke this function if the resource is hit
    CoapHandler handler_;
};

class HeatPump {
  public:

    HeatPump(NabtoDevice* device, nabto::FingerprintIAM& iam, nabto::HeatPumpPersisting& persisting)
        : device_(device), persisting_(persisting), fingerprintIAM_(iam)
    {
        connectionEventListener_ = nabto_device_listener_new(device);
        deviceEventListener_ = nabto_device_listener_new(device);

        connectionEventFuture_ = nabto_device_future_new(device);
        deviceEventFuture_ = nabto_device_future_new(device);
        iamChangedFuture_ = nabto_device_future_new(device_);

    }

    ~HeatPump() {
        nabto_device_future_free(connectionEventFuture_);
        nabto_device_future_free(deviceEventFuture_);
        nabto_device_future_free(iamChangedFuture_);

        nabto_device_listener_free(connectionEventListener_);
        nabto_device_listener_free(deviceEventListener_);
    }

    void init();

    void deinit() {
        if (connectionEventListener_) {
            nabto_device_listener_stop(connectionEventListener_);
        }
        if (deviceEventListener_) {
            nabto_device_listener_stop(deviceEventListener_);
        }
    }

    enum class Mode {
        COOL = 0,
        HEAT = 1,
        FAN = 2,
        DRY = 3,

    };

    NabtoDevice* getDevice() {
        return device_;
    }

    nabto::FingerprintIAM* getFPIAM() {
        return &fingerprintIAM_;
    }

    void setMode(Mode mode);
    void setTarget(double target);
    void setPower(bool on);
    const char* modeToString(HeatPump::Mode mode);
    const char* getModeString();


    json getState() {
        nlohmann::json state;
        state["Mode"] = persisting_.getHeatPumpMode();
        state["Target"] = persisting_.getHeatPumpTarget();
        state["Power"] = persisting_.getHeatPumpPower();
        state["Temperature"] = 22.3;
        return state;
    }

    bool beginPairing() {
        std::unique_lock<std::mutex> lock(mutex_);
        if (pairing_) {
            return false;
        }
        pairing_ = true;
        return true;
    }
    void pairingEnded() {
        std::unique_lock<std::mutex> lock(mutex_);
        pairing_ = false;
    }

    std::unique_ptr<std::thread> pairingThread_;

    std::unique_ptr<HeatPumpCoapRequestHandler> coapGetState;
    std::unique_ptr<HeatPumpCoapRequestHandler> coapPostPower;
    std::unique_ptr<HeatPumpCoapRequestHandler> coapPostMode;
    std::unique_ptr<HeatPumpCoapRequestHandler> coapPostTarget;
    std::unique_ptr<HeatPumpCoapRequestHandler> coapPostPairingButton;

  private:

    static void connectionEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData);
    void listenForConnectionEvents();
    void startWaitEvent();

    static void deviceEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData);
    void listenForDeviceEvents();
    void startWaitDevEvent();

    std::mutex mutex_;
    NabtoDevice* device_;

    nabto::HeatPumpPersisting& persisting_;

    bool pairing_ = false;
    uint64_t currentIamVersion_;

    NabtoDeviceListener* connectionEventListener_;
    NabtoDeviceFuture* connectionEventFuture_;
    NabtoDeviceConnectionRef connectionRef_;
    NabtoDeviceConnectionEvent connectionEvent_;

    NabtoDeviceListener* deviceEventListener_;
    NabtoDeviceFuture* deviceEventFuture_;
    NabtoDeviceEvent deviceEvent_;

    NabtoDeviceFuture* iamChangedFuture_;

    nabto::FingerprintIAM& fingerprintIAM_;
};

#endif
