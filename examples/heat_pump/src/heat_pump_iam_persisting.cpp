#include "heat_pump_iam_persisting.hpp"
#include "json_config.hpp"

#include <modules/iam_cpp/iam.hpp>
#include <modules/iam_cpp/iam_builder.hpp>
#include <modules/iam_cpp/iam_to_json.hpp>
#include <modules/iam_cpp/iam_builder.hpp>

namespace nabto {

HeatPumpIAMPersisting::HeatPumpIAMPersisting(iam::IAM& iam, const std::string& configFile)
    : configFile_(configFile), iam_(iam)
{

}

bool HeatPumpIAMPersisting::loadUsersFromConfig()
{
    if (!json_config_load(configFile_, config_)) {
        return false;
    }

    auto users = config_["Users"];

    std::vector<iam::User> us;
    iam::IAMToJson::usersFromJson(users, us);

    return true;
}


void HeatPumpIAMPersisting::loadIAM()
{
    // load static iam

    auto buttonPairingPolicy = iam::PolicyBuilder()
        .name("ButtonPairing")
        .addStatement(iam::StatementBuilder()
                      .allow()
                      .addAction("Pairing:Button")
                      .build())
        .build();

    auto readPolicy = iam::PolicyBuilder()
        .name("HeatPumpRead")
        .addStatement(iam::StatementBuilder()
                      .allow()
                      .addAction("HeatPump:Get")
                      .build())
        .build();

    auto writePolicy = iam::PolicyBuilder()
        .name("HeatPumpWrite")
        .addStatement(iam::StatementBuilder()
                      .allow()
                      .addAction("IAM:AddUser")
                      .addAction("IAM:GetUser")
                      .addAction("IAM:ListUsers")
                      .addAction("IAM:AddRoleToUser")
                      .addAction("IAM:RemoveRoleFromUser")
                      .build())
        .build();

    auto modifyOwnUserPolicy = iam::PolicyBuilder()
        .name("ModifyOwnUser")
        .addStatement(iam::StatementBuilder()
                      .allow()
                      .addAction("IAM:GetUser")
                      .addAction("IAM:ListUsers")
                      .addAction("IAM:AddFingerprint")
                      .addAction("IAM:RemoveFingerprint")
                      .addAttributeEqualCondition("Connection:UserId", "IAM:UserId")
                      .build())
        .build();

    nabto::iam::IAM iam;

    iam.addPolicy(buttonPairingPolicy);
    iam.addPolicy(readPolicy);
    iam.addPolicy(writePolicy);
    iam.addPolicy(modifyOwnUserPolicy);

    iam.addRole(iam::RoleBuilder().name("Unpaired").addPolicy("ButtonPairing").build());
    iam.addRole(iam::RoleBuilder().name("Owner")
                .addPolicy("HeatPumpWrite")
                .addPolicy("HeatPumpRead")
                .addPolicy("IAMFullAccess")
                .build());
    iam.addRole(iam::RoleBuilder().name("User")
                .addPolicy("HeatPumpRead")
                .addPolicy("HeatPumpWrite")
                .addPolicy("ModifyOwnUser")
                .build());
    iam.addRole(iam::RoleBuilder().name("Guest")
                .addPolicy("HeatPumpRead")
                .build());

    // load dynamic users

    loadUsersFromConfig();
}

void HeatPumpIAMPersisting::upsertUser(const iam::User& user)
{
    config_["Users"][user.getName()] = nabto::iam::IAMToJson::userToJson(user);
    json_config_save(configFile_, config_);
}

void HeatPumpIAMPersisting::deleteUser(const std::string& userId)
{
    config_["Users"].erase(userId);
    json_config_save(configFile_, config_);
}


} // namespace
