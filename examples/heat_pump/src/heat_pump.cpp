#include "heat_pump.hpp"
#include "json_config.hpp"

#include "heat_pump_set_power.hpp"
#include "heat_pump_set_target.hpp"
#include "heat_pump_set_mode.hpp"
#include "heat_pump_get.hpp"
#include "heat_pump_get_client_settings.hpp"

#include <examples/common/stdout_connection_event_handler.hpp>
#include <examples/common/stdout_device_event_handler.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include "button_press.hpp"

namespace nabto {
namespace examples {
namespace heat_pump {

HeatPump::HeatPump(NabtoDevice* device, nabto::fingerprint_iam::FingerprintIAM& iam, HeatPumpPersisting& persisting)
    : device_(device), persisting_(persisting), fingerprintIAM_(iam)
{
}

HeatPump::~HeatPump()
{
}

void HeatPump::init()
{
    persisting_.loadUsersIntoIAM(fingerprintIAM_);

    fingerprintIAM_.enableButtonPairing([](std::string fingerprint, std::function<void (bool accepted)> cb) {
            std::cout << "Allow the client with the fingerprint " << fingerprint << " to pair with the device? [y/n]" << std::endl;
            nabto::ButtonPress::wait(std::chrono::seconds(60), cb);
        });

    fingerprintIAM_.setUnpairedRole("Unpaired");
    fingerprintIAM_.setOwnerRole("Owner");
    fingerprintIAM_.setGuestRole("Guest");

    initCoapHandlers();

    stdoutConnectionEventHandler_ = nabto::examples::common::StdoutConnectionEventHandler::create(device_);
    stdoutDeviceEventHandler_ = nabto::examples::common::StdoutDeviceEventHandler::create(device_);

}

void HeatPump::initCoapHandlers()
{
    coapSetPower_ = nabto::examples::heat_pump::HeatPumpSetPower::create(*this, device_);
    coapSetTarget_ = nabto::examples::heat_pump::HeatPumpSetTarget::create(*this, device_);
    coapSetMode_ = nabto::examples::heat_pump::HeatPumpSetMode::create(*this, device_);
    coapGet_ = nabto::examples::heat_pump::HeatPumpGet::create(*this, device_);
    coapGetClientSettings_ = nabto::examples::heat_pump::HeatPumpGetClientSettings::create(*this, device_);
}

NabtoDeviceError HeatPump::initDevice()
{
    NabtoDeviceError ec;
    ec = nabto_device_set_product_id(device_, persisting_.getProductId().c_str());
    if (ec) {
        return ec;
    }
    ec = nabto_device_set_device_id(device_, persisting_.getDeviceId().c_str());
    if (ec) {
        return ec;
    }
    ec = nabto_device_set_server_url(device_, persisting_.getServer().c_str());
    if (ec) {
        return ec;
    }
    ec = nabto_device_set_private_key(device_, persisting_.getPrivateKey().c_str());
    if (ec) {
        return ec;
    }

    ec = nabto_device_enable_mdns(device_);
    if (ec) {
        return ec;
    }
    ec = nabto_device_set_log_std_out_callback(device_);
    if (ec) {
        return ec;
    }

    // run application
    ec = nabto_device_start(device_);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to start device" << std::endl;
        return ec;
    }
    return NABTO_DEVICE_EC_OK;
}

void HeatPump::setLogLevel(const std::string& logLevel)
{
    nabto_device_set_log_level(device_, logLevel.c_str());
}

void HeatPump::printHeatpumpInfo()
{
    char* fpTemp = NULL;
    nabto_device_get_device_fingerprint_hex(device_, &fpTemp);
    std::string fingerprint(fpTemp);
    nabto_device_string_free(fpTemp);

    std::cout << "Device " << persisting_.getProductId() << "." << persisting_.getDeviceId() << " Started with fingerprint " << fingerprint << std::endl;
    std::cout << " client server url " << persisting_.getClientServerUrl() << " client server key " << persisting_.getClientServerKey() << std::endl;
}

void HeatPump::setMode(Mode mode)
{
    persisting_.setHeatPumpMode(modeToString(mode));
    persisting_.save();
}
void HeatPump::setTarget(double target)
{
    persisting_.setHeatPumpTarget(target);
    persisting_.save();
}

void HeatPump::setPower(bool power)
{
    persisting_.setHeatPumpPower(power);
    persisting_.save();
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

bool HeatPump::checkAccess(NabtoDeviceCoapRequest* request, const std::string& action)
{
    if (!fingerprintIAM_.checkAccess(nabto_device_coap_request_get_connection_ref(request), action)) {
        nabto_device_coap_error_response(request, 403, "Unauthorized");
        nabto_device_coap_request_free(request);
        return false;
    }
    return true;
}

} } } // namespace
