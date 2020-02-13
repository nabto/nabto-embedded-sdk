#include "heat_pump_persisting.hpp"
#include "json_config.hpp"

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
    users_[user.getUserId()] = nabto::fingerprint_iam::FingerprintIAMJson::userToJson(user);
    save();
}

void HeatPumpPersisting::deleteUser(const std::string& userId)
{
    users_.erase(userId);
    save();
}

void HeatPumpPersisting::deleteAllUsers()
{
    users_.clear();
    save();
}

void HeatPumpPersisting::save()
{
    config_["Users"].clear();
    for (auto u : users_) {
        config_["Users"] = nlohmann::json::array();
        config_["Users"].push_back(u.second);
    }
    json_config_save(configFile_, config_);
}


} } } // namespace
