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

void HeatPump::connectionEvent(NabtoDeviceFuture* fut, NabtoDeviceError err, void* userData)
{
    NabtoDeviceFuture* future;
    HeatPump* hp = (HeatPump*)userData;
    nabto_device_future_free(fut);
    if (err != NABTO_DEVICE_EC_OK) {
        std::cout << "Connection event called back with error: " << err << std::endl;
        nabto_device_event_handler_free(hp->connectionEventHandler_);
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
        NabtoDeviceError ec = nabto_device_event_handler_create_future(hp->connectionEventHandler_, &future);
        if (ec != NABTO_DEVICE_EC_OK) {
            std::cerr << "Failed to create connection event future with ec: " << ec << std::endl;
            nabto_device_event_handler_free(hp->connectionEventHandler_);
        }
        ec = nabto_device_future_set_callback(future, &HeatPump::connectionEvent, hp);
        if (ec != NABTO_DEVICE_EC_OK) {
            std::cerr << "Failed to set future callback with ec: " << ec << std::endl;
            nabto_device_future_free(future);
            nabto_device_event_handler_free(hp->connectionEventHandler_);
            return;
        }
    }
}

void HeatPump::listenForConnectionEvents()
{
    NabtoDeviceFuture* future;
    connectionEventHandler_ = nabto_device_listen_connection_event(device_, &connectionRef_, &connectionEvent_);
    if (connectionEventHandler_ == NULL) {
        std::cerr << "Failed to listen to connection events" << std::endl;
        return;
    }
    NabtoDeviceError ec = nabto_device_event_handler_create_future(connectionEventHandler_, &future);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to create connection event future with ec: " << ec << std::endl;
        nabto_device_event_handler_free(connectionEventHandler_);
    }
    ec = nabto_device_future_set_callback(future, &HeatPump::connectionEvent, this);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to set future callback with ec: " << ec << std::endl;
        nabto_device_future_free(future);
        nabto_device_event_handler_free(connectionEventHandler_);
        return;
    }


}
