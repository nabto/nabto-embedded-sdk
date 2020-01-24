#include "heat_pump_iam_persisting.hpp"
#include "json_config.hpp"

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
                      .addCondition(iam::ConditionBuilder()
                                    .attributeEqual("Connection:UserId", "IAM:UserId")
                                    .build())
                      .build())
        .build();

    iam.addPolicy(buttonPairingPolicy);
    iam.addPolicy(readPolicy);
    iam.addPolicy(writePolicy);
    iam.addPolicy(modifyOwnUserPolicy);

    iam.addRole(RoleBuilder().name("Unpaired").addPolicy("ButtonPairing").build());
    iam.addRole(RoleBuilder()
                .name("Owner")
                .addPolicy("HeatPumpWrite")
                .addPolicy("HeatPumpRead")
                .addPolicy("IAMFullAccess")
                .build());
    iam.addRole(RoleBuilder()
                .name("User")
                .addPolicy("HeatPumpRead")
                .addPolicy("HeatPumpWrite")
                .addPolicy("ModifyOwnUser")
                .build());
    iam.addRole(RoleBuilder()
                .name("Guest")
                .addPolicy("HeatPumpRead")
                .build());

    // load dynamic users

    loadUsersFromConfig();

    iam.enablePersisting();
}

void HeatPumpIAMPersisting::upsertUser(const iam::User& user)
{

}

void HeatPumpIAMPersisting::deleteUser(const std::string& userId)
{

}


} // namespace
