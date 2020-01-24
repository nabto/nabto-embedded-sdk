#include "heat_pump_iam_persisting.hpp"

namespace nabto {

HeatPumpIAMPersisting::HeatPumpIAMPersisting(iam::Iam& iam, const std::string& configFile)
    : configFile_(configFile), iam_(iam)
{

}

void HeatPumpIAMPersisting::loadIAM()
{
    // load static iam

    auto buttonPairingPolicy = PolicyBuilder()
        .name("ButtonPairing")
        .addStatement(StatementBuilder()
                      .allow()
                      .addAction("Pairing:Button")
                      .build())
        .build();

    auto readPolicy = PolicyBuilder()
        .name("HeatPumpRead")
        .addStatement(StatementBuilder()
                      .allow()
                      .addAction("HeatPump:Get")
                      .build())
        .build();

    auto writePolicy = PolicyBuilder()
        .name("HeatPumpWrite")
        .addStatement(StatementBuilder()
                      .allow()
                      .addAction("IAM:AddUser")
                      .addAction("IAM:GetUser")
                      .addAction("IAM:ListUsers")
                      .addAction("IAM:AddRoleToUser")
                      .addAction("IAM:RemoveRoleFromUser")
                      .build())
        .build();

    auto modifyOwnUserPolicy = PolicyBuilder()
        .name("ModifyOwnUser")
        .addStatement(StatementBuilder()
                      .allow()
                      .addAction("IAM:GetUser")
                      .addAction("IAM:ListUsers")
                      .addAction("IAM:AddFingerprint")
                      .addAction("IAM:RemoveFingerprint")
                      .addCondition(ConditionBuilder()
                                    .attributeEqual("Connection:UserId", "IAM:UserId")
                                    .build())
                      .build())
        .build();

    iam.addPolicy(buttonPairingPolicy);
    iam.addPolicy(readPolicy);
    iam.addPolicy(writePolicy);
    iam.addPolicy(modifyOwnUserPolicy);



    // load dynamic users
}

void HeatPumpIAMPersisting::upsertUser(const iam::User& user)
{

}

void HeatPumpIAMPersisting::deleteUser(const std::string& userId)
{

}


} // namespace
