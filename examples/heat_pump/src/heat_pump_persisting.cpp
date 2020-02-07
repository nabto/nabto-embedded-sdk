#include "heat_pump_persisting.hpp"
#include "json_config.hpp"

#include <modules/iam_cpp/iam.hpp>
#include <modules/iam_cpp/iam_builder.hpp>
#include <modules/iam_cpp/iam_to_json.hpp>
#include <modules/iam_cpp/iam_builder.hpp>
#include <modules/fingerprint_iam/fingerprint_iam_json.hpp>

namespace nabto {

HeatPumpPersisting::HeatPumpPersisting(const std::string& configFile)
    : configFile_(configFile)
{

}

bool HeatPumpPersisting::loadUsersIntoIAM(FingerprintIAM& iam)
{
    return FingerprintIAMJson::loadUsersFromJson(iam, config_["Users"]);
}

bool HeatPumpPersisting::load()
{
    if (!json_config_load(configFile_, config_)) {
        return false;
    }
    return true;
}

void HeatPumpPersisting::upsertUser(const User& user)
{
    config_["Users"][user.getUserId()] = nabto::FingerprintIAMJson::userToJson(user);
    save();
}

void HeatPumpPersisting::deleteUser(const std::string& userId)
{
    config_["Users"].erase(userId);
    save();
}

void HeatPumpPersisting::save()
{
    json_config_save(configFile_, config_);
}


} // namespace
