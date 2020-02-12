#include "tcptunnel_default_policies.hpp"

#include <modules/iam_cpp/iam_builder.hpp>
#include <modules/fingerprint_iam/fingerprint_iam.hpp>
#include <modules/fingerprint_iam/fingerprint_iam_json.hpp>
#include <modules/iam_cpp/iam_to_json.hpp>

#include <examples/common/json_config.hpp>

#include <nlohmann/json.hpp>



void insertPolicy(nlohmann::json& policies, const nabto::iam::PolicyBuilder& policy)
{
    policies[policy.getName()] = nabto::iam::IAMToJson::policyToJson(policy);
}

void insertRole(nlohmann::json& roles, const nabto::iam::RoleBuilder& role)
{
    roles[role.getName()] = nabto::iam::IAMToJson::roleToJson(role);
}

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
    auto ownerRole = nabto::iam::RoleBuilder("Owner").addPolicy("TunnelAll").addPolicy("Paired");
    auto guestRole = nabto::iam::RoleBuilder("Guest").addPolicy("TunnelAll").addPolicy("Paired");

    nlohmann::json root;

    nlohmann::json policies;
    insertPolicy(policies, passwordPairingPolicy);
    insertPolicy(policies, tunnelAllPolicy);
    insertPolicy(policies, pairedPolicy);

    root["Policies"] = policies;

    nlohmann::json roles;
    insertRole(roles, unpairedRole);
    insertRole(roles, ownerRole);
    insertRole(roles, guestRole);

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

    if (!policies.is_object()) {
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