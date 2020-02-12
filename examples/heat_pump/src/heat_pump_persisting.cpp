#include "heat_pump_persisting.hpp"
#include "json_config.hpp"

#include <modules/iam_cpp/iam.hpp>
#include <modules/iam_cpp/iam_builder.hpp>
#include <modules/iam_cpp/iam_to_json.hpp>
#include <modules/iam_cpp/iam_builder.hpp>
#include <modules/fingerprint_iam/fingerprint_iam_json.hpp>

namespace nabto {
namespace examples {
namespace heat_pump {

HeatPumpPersisting::HeatPumpPersisting(const std::string& configFile)
    : configFile_(configFile)
{

}

bool HeatPumpPersisting::loadUsersIntoIAM(fingerprint_iam::FingerprintIAM& iam)
{
    return fingerprint_iam::FingerprintIAMJson::loadUsersFromJson(iam, config_["Users"]);
}

bool HeatPumpPersisting::load()
{
    if (!json_config_load(configFile_, config_)) {
        initDefault();
    }
    return true;
}

bool HeatPumpPersisting::initDefault()
{
    setHeatPumpMode("COOL");
    setHeatPumpPower(false);
    setHeatPumpTarget(22.3);
    save();
    return true;
}

void HeatPumpPersisting::upsertUser(const fingerprint_iam::User& user)
{
    config_["Users"][user.getUserId()] = nabto::fingerprint_iam::FingerprintIAMJson::userToJson(user);
    save();
}

void HeatPumpPersisting::deleteUser(const std::string& userId)
{
    config_["Users"].erase(userId);
    save();
}

void HeatPumpPersisting::deleteAllUsers()
{
    config_["Users"].clear();
    save();
}

void HeatPumpPersisting::save()
{
    json_config_save(configFile_, config_);
}


} } } // namespace
