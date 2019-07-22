#include "heatpump.hpp"
#include "heatpump_config.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdio.h>
#include <stdlib.h>

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

void Heatpump::setMode(Mode mode)
{
    state_["HeatPump"]["Mode"] = modeToString(mode);
}
void Heatpump::setTarget(double target)
{
    state_["HeatPump"]["Target"] = target;
}

void Heatpump::setPower(bool power)
{
    state_["HeatPump"]["Power"] = power;
}

Heatpump::Mode Heatpump::getMode()
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

double Heatpump::getTarget()
{
    try {
        return state_["HeatPump"]["Target"].get<double>();
    } catch (std::exception& e) {

    }

    // default sane value 42/2
    return 21;
}

bool Heatpump::getPower()
{
    try {
        return state_["HeatPump"]["Power"].get<bool>();
    } catch (std::exception& e) {
    }

    // sane value
    return false;
}

double Heatpump::getTemperature()
{
    // TODO implement changing temperature logic
    return 22.3;
}

const char* Heatpump::getModeString()
{
    return modeToString(getMode());
}

const char* Heatpump::modeToString(Heatpump::Mode mode)
{
    switch (mode) {
        case Heatpump::Mode::COOL: return "COOL";
        case Heatpump::Mode::HEAT: return "HEAT";
        case Heatpump::Mode::FAN: return "FAN";
        case Heatpump::Mode::DRY: return "DRY";
        default: return "UNKNOWN";
    }
}
