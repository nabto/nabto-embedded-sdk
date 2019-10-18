#include "heat_pump.hpp"
#include "json_config.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>

void HeatPump::init() {
    listenForIamChanges();
    listenForConnectionEvents();
    listenForDeviceEvents();
}

bool validate_config(const json& config) {
    try {
        config["ProductId"].get<std::string>();
        config["DeviceId"].get<std::string>();
        config["Server"].get<std::string>();
        config["PrivateKey"].get<std::string>();
        config["Iam"]["Users"];
        config["Iam"]["Roles"];
        config["Iam"]["Policies"];
    } catch (std::exception& e) {
        return false;
    }
    return true;
}

void HeatPump::setMode(Mode mode)
{
    config_["HeatPump"]["Mode"] = modeToString(mode);
    saveConfig();
}
void HeatPump::setTarget(double target)
{
    config_["HeatPump"]["Target"] = target;
    saveConfig();
}

void HeatPump::setPower(bool power)
{
    config_["HeatPump"]["Power"] = power;
    saveConfig();
}

const char* HeatPump::modeToString(HeatPump::Mode mode)
{
    switch (mode) {
        case HeatPump::Mode::COOL: return "COOL";
        case HeatPump::Mode::HEAT: return "HEAT";
        case HeatPump::Mode::FAN: return "FAN";
        case HeatPump::Mode::DRY: return "DRY";
        default: return "UNKNOWN";
    }
}


void HeatPump::iamChanged(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    nabto_device_future_free(fut);
    if (err != NABTO_DEVICE_EC_OK) {
        return;
    }
    HeatPump* hp = (HeatPump*)userData;
    hp->saveConfig();
    hp->listenForIamChanges();
}

void HeatPump::listenForIamChanges()
{
    NabtoDeviceFuture* future = nabto_device_iam_listen_for_changes(device_, currentIamVersion_);
    if (!future) {
        return;
    }
    nabto_device_future_set_callback(future, HeatPump::iamChanged, this);
}

void HeatPump::saveConfig()
{
    json config = config_;

    uint64_t version;
    size_t used;
    if (nabto_device_iam_dump(device_, &version, NULL, 0, &used) != NABTO_DEVICE_EC_OUT_OF_MEMORY) {
        return;
    }

    std::vector<uint8_t> buffer(used);
    if(nabto_device_iam_dump(device_, &version, buffer.data(), buffer.size(), &used) != NABTO_DEVICE_EC_OK) {
        return;
    }
    config["Iam"] = json::from_cbor(buffer);
    currentIamVersion_ = version;

    std::string tmpFile = "tmp.json";
    json_config_save(configFile_, config);
    std::cout << "Configuration saved to file" << std::endl;
}

void HeatPump::startWaitEvent()
{
    NabtoDeviceFuture* future;
    NabtoDeviceError ec = nabto_device_listener_listen(connectionEventListener_, &future);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to create connection event future with ec: " << ec << std::endl;
        nabto_device_listener_free(connectionEventListener_);
        connectionEventListener_ = NULL;
        return;
    }
    ec = nabto_device_future_set_callback(future, &HeatPump::connectionEvent, this);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to set future callback with ec: " << ec << std::endl;
        nabto_device_future_free(future);
        nabto_device_listener_free(connectionEventListener_);
        connectionEventListener_ = NULL;
        return;
    }
}

void HeatPump::connectionEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    HeatPump* hp = (HeatPump*)userData;
    nabto_device_future_free(fut);
    if (err != NABTO_DEVICE_EC_OK) {
        std::cout << "Connection event called back with error: " << err << std::endl;
        nabto_device_listener_free(hp->connectionEventListener_);
        return;
    } else {
        if (hp->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_OPENED) {
            std::cout << "New connection opened with reference: " << hp->connectionRef_ << std::endl;
        } else if (hp->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_CLOSED) {
            std::cout << "Connection with reference: " << hp->connectionRef_ << " was closed" << std::endl;
        } else if (hp->connectionEvent_ == NABTO_DEVICE_CONNECTION_EVENT_CHANNEL_CHANGED) {
            std::cout << "Connection with reference: " << hp->connectionRef_ << " changed channel" << std::endl;
        } else {
            std::cout << "Unknown connection event: " << hp->connectionEvent_ << " on connection reference: " << hp->connectionRef_ << std::endl;
        }
    }
    hp->startWaitEvent();

}

void HeatPump::listenForConnectionEvents()
{
    connectionEventListener_ = nabto_device_connection_events_listener_new(device_, &connectionRef_, &connectionEvent_);
    if (connectionEventListener_ == NULL) {
        std::cerr << "Failed to listen to connection events" << std::endl;
        return;
    }
    startWaitEvent();
}

void HeatPump::startWaitDevEvent()
{
    NabtoDeviceFuture* future;
    NabtoDeviceError ec = nabto_device_listener_listen(deviceEventListener_, &future);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to create device event future with ec: " << ec << std::endl;
        nabto_device_listener_free(deviceEventListener_);
        deviceEventListener_ = NULL;
        return;
    }
    ec = nabto_device_future_set_callback(future, &HeatPump::deviceEvent, this);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to set future callback with ec: " << ec << std::endl;
        nabto_device_future_free(future);
        nabto_device_listener_free(deviceEventListener_);
        deviceEventListener_ = NULL;
        return;
    }
}

void HeatPump::deviceEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    HeatPump* hp = (HeatPump*)userData;
    nabto_device_future_free(fut);
    if (err != NABTO_DEVICE_EC_OK) {
        std::cout << "Device event called back with error: " << err << std::endl;
        nabto_device_listener_free(hp->deviceEventListener_);
        return;
    } else {
        if (hp->deviceEvent_ == NABTO_DEVICE_EVENT_ATTACHED) {
            std::cout << "Device is now attached" << std::endl;
        } else if (hp->deviceEvent_ == NABTO_DEVICE_EVENT_DETACHED) {
            std::cout << "Device is now detached" << std::endl;
        } else if (hp->deviceEvent_ == NABTO_DEVICE_EVENT_FAILURE) {
            std::cout << "Device is now in a failure state!" << std::endl;
        } else {
            std::cout << "Unknown device event: " << hp->deviceEvent_ << std::endl;
        }
    }
    hp->startWaitDevEvent();

}

void HeatPump::listenForDeviceEvents()
{
    deviceEventListener_ = nabto_device_events_listener_new(device_, &deviceEvent_);
    if (deviceEventListener_ == NULL) {
        std::cerr << "Failed to listen to device events" << std::endl;
        return;
    }
    startWaitDevEvent();
}
