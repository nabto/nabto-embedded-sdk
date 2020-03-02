#include "heat_pump_persisting.hpp"
#include "json_config.hpp"

#include <modules/iam_cpp/iam_builder.hpp>
#include <modules/iam_cpp/iam_to_json.hpp>
#include <modules/iam_cpp/iam_builder.hpp>
#include <modules/fingerprint_iam/fingerprint_iam_json.hpp>

#include <examples/common/random_string.hpp>

namespace nabto {
namespace examples {
namespace heat_pump {

HeatPumpPersisting::HeatPumpPersisting(const std::string& configFile, fingerprint_iam::FingerprintIAM& iam)
    : configFile_(configFile), iam_(iam)
{
}

bool HeatPumpPersisting::load()
{
    if (!json_config_load(configFile_, config_)) {
        initDefault();
        return true;
    } else {
        return fingerprint_iam::FingerprintIAMJson::loadUsersFromJson(iam_, config_["Users"]);
    }
}

bool HeatPumpPersisting::initDefault()
{
    setHeatPumpMode("COOL");
    setHeatPumpPower(false);
    setHeatPumpTarget(22.3);
    config_["PairingPassword"] = nabto::examples::common::random_string(20);
    config_["PairingServerConnectToken"] = nabto::examples::common::random_string(20);
    save();
    return true;
}

void HeatPumpPersisting::upsertUser(const std::string& id)
{
    save();
}

void HeatPumpPersisting::deleteUser(const std::string& id)
{
    save();
}

void HeatPumpPersisting::save()
{
    config_["Users"].clear();
    config_["Users"] = nlohmann::json::array();
    for (auto u : iam_.getUsers()) {
        config_["Users"].push_back(nabto::fingerprint_iam::FingerprintIAMJson::userToJson(*u));
    }
    json_config_save(configFile_, config_);
}


} } } // namespace
