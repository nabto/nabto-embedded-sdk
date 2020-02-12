#include "heat_pump.hpp"
#include "json_config.hpp"

#include "heat_pump_set_power.hpp"
#include "heat_pump_set_target.hpp"
#include "heat_pump_set_mode.hpp"
#include "heat_pump_get.hpp"

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

HeatPump::HeatPump(NabtoDevice* device, const std::string& privateKey, nabto::examples::common::DeviceConfig& dc, HeatPumpPersisting& persisting)
    : device_(device), privateKey_(privateKey), dc_(dc), persisting_(persisting), fingerprintIAM_(device, persisting)
{

}

HeatPump::~HeatPump()
{
}

bool HeatPump::init()
{
    if (initDevice() != NABTO_DEVICE_EC_OK) {
        return false;
    }
    loadIamPolicy();
    persisting_.loadUsersIntoIAM(fingerprintIAM_);

    fingerprintIAM_.enableButtonPairing([](std::string fingerprint, std::function<void (bool accepted)> cb) {
            std::cout << "Allow the client with the fingerprint " << fingerprint << " to pair with the device? [y/n]" << std::endl;
            nabto::ButtonPress::wait(std::chrono::seconds(60), cb);
        });

    fingerprintIAM_.setUnpairedRole("Unpaired");
    fingerprintIAM_.setOwnerRole("Owner");
    fingerprintIAM_.setGuestRole("Guest");
    fingerprintIAM_.enableClientSettings(dc_.getClientServerUrl(), dc_.getClientServerKey());

    initCoapHandlers();

    stdoutConnectionEventHandler_ = nabto::examples::common::StdoutConnectionEventHandler::create(device_);
    stdoutDeviceEventHandler_ = nabto::examples::common::StdoutDeviceEventHandler::create(device_);
    return true;

}

void HeatPump::initCoapHandlers()
{
    coapSetPower_ = nabto::examples::heat_pump::HeatPumpSetPower::create(*this, device_);
    coapSetTarget_ = nabto::examples::heat_pump::HeatPumpSetTarget::create(*this, device_);
    coapSetMode_ = nabto::examples::heat_pump::HeatPumpSetMode::create(*this, device_);
    coapGet_ = nabto::examples::heat_pump::HeatPumpGet::create(*this, device_);
}

NabtoDeviceError HeatPump::initDevice()
{
    NabtoDeviceError ec;
    ec = nabto_device_set_product_id(device_, dc_.getProductId().c_str());
    if (ec) {
        return ec;
    }
    ec = nabto_device_set_device_id(device_, dc_.getDeviceId().c_str());
    if (ec) {
        return ec;
    }
    ec = nabto_device_set_server_url(device_, dc_.getServer().c_str());
    if (ec) {
        return ec;
    }
    ec = nabto_device_set_private_key(device_, privateKey_.c_str());
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
    char* fpTemp;
    nabto_device_get_device_fingerprint_hex(device_, &fpTemp);
    std::string fp(fpTemp);
    nabto_device_string_free(fpTemp);

    std::cout << "######## Nabto heat pump device ########" << std::endl;
    std::cout << "# Product ID:       " << dc_.getProductId() << std::endl;
    std::cout << "# Device ID:        " << dc_.getDeviceId() << std::endl;
    std::cout << "# Fingerprint:      " << fp << std::endl;
    std::cout << "# Client Server Url " << dc_.getClientServerUrl() << std::endl;
    std::cout << "# Client Server Key " << dc_.getClientServerKey() << std::endl;
    std::cout << "# Version:          " << nabto_device_version() << std::endl;
    std::cout << "######## " << std::endl;
}

void HeatPump::dumpIam()
{
    fingerprintIAM_.dumpUsers();
    fingerprintIAM_.dumpRoles();
    fingerprintIAM_.dumpPolicies();
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

void HeatPump::loadIamPolicy()
{
    auto buttonPairingPolicy = nabto::iam::PolicyBuilder("ButtonPairing")
        .addStatement(nabto::iam::StatementBuilder(nabto::iam::Effect::ALLOW)
                      .addAction("Pairing:Button"))
        .build();

    auto readPolicy = nabto::iam::PolicyBuilder("HeatPumpRead")
        .addStatement(nabto::iam::StatementBuilder(nabto::iam::Effect::ALLOW)
                      .addAction("HeatPump:Get"))
        .build();

    auto writePolicy = nabto::iam::PolicyBuilder("HeatPumpWrite")
        .addStatement(nabto::iam::StatementBuilder(nabto::iam::Effect::ALLOW)
                      .addAction("HeatPump:Set"))
        .build();

    fingerprintIAM_.addPolicy(buttonPairingPolicy);
    fingerprintIAM_.addPolicy(readPolicy);
    fingerprintIAM_.addPolicy(writePolicy);

    fingerprintIAM_.addRole(nabto::iam::RoleBuilder("Unpaired").addPolicy("ButtonPairing"));
    fingerprintIAM_.addRole(nabto::iam::RoleBuilder("Owner")
                            .addPolicy("HeatPumpWrite")
                            .addPolicy("HeatPumpRead"));
    fingerprintIAM_.addRole(nabto::iam::RoleBuilder("User")
                            .addPolicy("HeatPumpRead")
                            .addPolicy("HeatPumpWrite"));
    fingerprintIAM_.addRole(nabto::iam::RoleBuilder("Guest")
                            .addPolicy("HeatPumpRead"));
}


} } } // namespace
