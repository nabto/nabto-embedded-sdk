#include "tcptunnel_default_policies.hpp"

#include <modules/iam_cpp/iam_builder.hpp>
#include <modules/fingerprint_iam/fingerprint_iam.hpp>
#include <modules/fingerprint_iam/fingerprint_iam_json.hpp>
#include <modules/iam_cpp/iam_to_json.hpp>

#include <examples/common/json_config.hpp>

#include <nlohmann/json.hpp>


bool init_default_policies(const std::string& policiesFile)
{
    auto passwordPairingPolicy = nabto::iam::PolicyBuilder("PasswordPairing")
        .addStatement(nabto::iam::StatementBuilder(nabto::iam::Effect::ALLOW)
                      .addAction("Pairing:Get")
                      .addAction("Pairing:Password"));


    auto tunnelAllPolicy = nabto::iam::PolicyBuilder("TunnelAll")
        .addStatement(nabto::iam::StatementBuilder(nabto::iam::Effect::ALLOW)
                      .addAction("TcpTunnel:Create")
                      .addAction("TcpTunnel:Destroy"));

    auto pairedPolicy = nabto::iam::PolicyBuilder("Paired")
        .addStatement(nabto::iam::StatementBuilder(nabto::iam::Effect::ALLOW)
                      .addAction("Pairing:Get"));

    auto unpairedRole = nabto::iam::RoleBuilder("Unpaired").addPolicy("PasswordPairing");
    auto adminRole = nabto::iam::RoleBuilder("Admin").addPolicy("TunnelAll").addPolicy("Paired");
    auto userRole = nabto::iam::RoleBuilder("User").addPolicy("TunnelAll").addPolicy("Paired");

    nlohmann::json root;

    nlohmann::json policies = nlohmann::json::array();
    policies.push_back(nabto::iam::IAMToJson::policyToJson(passwordPairingPolicy));
    policies.push_back(nabto::iam::IAMToJson::policyToJson(tunnelAllPolicy));
    policies.push_back(nabto::iam::IAMToJson::policyToJson(pairedPolicy));

    root["Policies"] = policies;

    nlohmann::json roles = nlohmann::json::array();
    roles.push_back(nabto::iam::IAMToJson::roleToJson(unpairedRole));
    roles.push_back(nabto::iam::IAMToJson::roleToJson(adminRole));
    roles.push_back(nabto::iam::IAMToJson::roleToJson(userRole));

    root["Roles"] = roles;

    json_config_save(policiesFile, root);

    return true;
}

bool load_policies(const std::string& policiesFile, nabto::fingerprint_iam::FingerprintIAM& iam)
{
    nlohmann::json root;
    if (!json_config_load(policiesFile, root)) {
        return false;
    }

    nlohmann::json roles = root["Roles"];
    nlohmann::json policies = root["Policies"];

    if (!policies.is_array()) {
        return false;
    }

    for (auto it = policies.begin(); it != policies.end(); it++)
    {
        auto parsed = nabto::iam::IAMToJson::policyFromJson(*it);
        if (parsed != nullptr) {
            iam.addPolicy(*parsed);
        }
    }

    nabto::fingerprint_iam::FingerprintIAMJson::loadRoles(iam, roles);

    return true;

}

bool init_default_services(const std::string& servicesFile)
{
    nlohmann::json services = nlohmann::json::array();
    nlohmann::json service;
    service["Id"] = "ssh";
    service["Type"] = "ssh";
    service["Host"] = "127.0.0.1";
    service["Port"] = 22;

    services.push_back(service);

    json_config_save(servicesFile, services);
    return true;
}

bool load_services(const std::string& servicesFile, NabtoDevice* device)
{
    nlohmann::json root;
    if (!json_config_load(servicesFile, root)) {
        return false;
    }

    if (!root.is_array()) {
        return false;
    }

    for (auto s : root) {
        if (s.is_object()) {
            try {
                std::string id = s["Id"].get<std::string>();
                std::string type = s["Type"].get<std::string>();
                std::string host = s["Host"].get<std::string>();
                uint16_t port = s["Port"].get<uint16_t>();
                NabtoDeviceError ec = nabto_device_add_tcp_tunnel_service(device, id.c_str(), type.c_str(), host.c_str(), port);
                if (ec != NABTO_DEVICE_EC_OK) {
                    std::cerr << "Could not add service: " << s << std::endl;
                    return false;
                }
            } catch (std::exception& e) {
                std::cerr << "Could not parse service: " << s << std::endl;
                return false;
            }
        }
    }
    return true;
}
