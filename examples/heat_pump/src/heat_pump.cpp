#include "heat_pump.hpp"
#include "heat_pump_config.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>

void HeatPump::init() {
    listenForIamChanges();
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
    state_["HeatPump"]["Mode"] = modeToString(mode);
}
void HeatPump::setTarget(double target)
{
    state_["HeatPump"]["Target"] = target;
}

void HeatPump::setPower(bool power)
{
    state_["HeatPump"]["Power"] = power;
}

HeatPump::Mode HeatPump::getMode()
{
    try {
        std::string mode = state_["HeatPump"]["Mode"].get<std::string>();
        if (mode == "COOL") {
            return Mode::COOL;
        } else if (mode == "HEAT") {
            return Mode::HEAT;
        } else if (mode == "FAN") {
            return Mode::FAN;
        } else if (mode == "DRY") {
            return Mode::DRY;
        }
    } catch (std::exception& e) {
    }
    // default
    return Mode::COOL;
}

double HeatPump::getTarget()
{
    try {
        return state_["HeatPump"]["Target"].get<double>();
    } catch (std::exception& e) {

    }

    // default sane value 42/2
    return 21;
}

bool HeatPump::getPower()
{
    try {
        return state_["HeatPump"]["Power"].get<bool>();
    } catch (std::exception& e) {
    }

    // sane value
    return false;
}

double HeatPump::getTemperature()
{
    // TODO implement changing temperature logic
    return 22.3;
}

const char* HeatPump::getModeString()
{
    return modeToString(getMode());
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
    heat_pump_save_config(configFile_, tmpFile, config);
    std::cout << "Configuration saved to file" << std::endl;
}
