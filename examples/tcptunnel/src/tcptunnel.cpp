#include "tcptunnel.hpp"

#include "json_config.hpp"
#include "tcptunnel_default_policies.hpp"

#include <nabto/nabto_device_experimental.h>

#include <iostream>

namespace nabto {
namespace examples {
namespace tcptunnel {

bool TcpTunnel::initDevice()
{
    NabtoDeviceError ec;
    ec = nabto_device_set_product_id(device_, deviceConfig_.getProductId().c_str());
    if (ec) {
        std::cerr << "Could not set product id" << std::endl;
        return false;
    }
    ec = nabto_device_set_device_id(device_, deviceConfig_.getDeviceId().c_str());
    if (ec) {
        std::cerr << "Could not set device id" << std::endl;
        return false;
    }
    ec = nabto_device_set_server_url(device_, deviceConfig_.getServer().c_str());
    if (ec) {
        std::cerr << "Could not set server url" << std::endl;
        return false;
    }
    ec = nabto_device_set_private_key(device_, privateKey_.c_str());
    if (ec) {
        std::cerr << "Could not set private key" << std::endl;
        return false;
    }

    ec = nabto_device_enable_mdns(device_);
    if (ec) {
        std::cerr << "Failed to enable mdns" << std::endl;
        return false;
    }
    ec = nabto_device_enable_tcp_tunnelling(device_);
    if (ec) {
        std::cerr << "Failed to enable tcp tunnelling" << std::endl;
        return false;
    }
    ec = nabto_device_set_log_std_out_callback(device_);
    if (ec) {
        std::cerr << "Failed to enable stdour logging" << std::endl;
        return false;
    }

    // run application
    ec = nabto_device_start(device_);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to start device" << std::endl;
        return false;
    }
    return true;
}

bool TcpTunnel::initAccessControl()
{
    state_.loadUsersIntoIAM(fingerprintIAM_);
    fingerprintIAM_.enablePasswordPairing(state_.getPairingPassword());
    return true;
}

bool TcpTunnel::loadIamConfig()
{
    if (!json_config_exists(policiesFile_)) {
        std::cout << "The policies file is not found, creating a new file with default policies" << std::endl;
        init_default_policies(policiesFile_);
    }

    nlohmann::json root;

    load_policies(policiesFile_, fingerprintIAM_);
    return true;
}

void TcpTunnel::dumpIam()
{
    fingerprintIAM_.dumpUsers();
    fingerprintIAM_.dumpRoles();
    fingerprintIAM_.dumpPolicies();
}


} } } // namespace
