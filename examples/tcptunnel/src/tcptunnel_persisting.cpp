#include "tcptunnel_persisting.hpp"

#include <examples/common/json_config.hpp>
#include <examples/common/random_string.hpp>
#include <modules/fingerprint_iam/fingerprint_iam.hpp>
#include <modules/fingerprint_iam/fingerprint_iam_json.hpp>

namespace nabto {
namespace examples {
namespace tcptunnel {

bool TcpTunnelPersisting::load()
{
    if (!json_config_load(configFile_, config_)) {
        initDefault();
        return true;
    } else {
        return fingerprint_iam::FingerprintIAMJson::loadUsersFromJson(iam_, config_["Users"]);
    }
}

bool TcpTunnelPersisting::initDefault()
{
    config_["PairingPassword"] = nabto::examples::common::random_string(16);
    save();
    return true;
}

void TcpTunnelPersisting::upsertUser(const std::string& id)
{
    save();
}

void TcpTunnelPersisting::deleteUser(const std::string& id)
{
    save();
}

void TcpTunnelPersisting::save()
{
    config_["Users"].clear();
    config_["Users"] = nlohmann::json::array();
    for (auto u : iam_.getUsers()) {
        config_["Users"].push_back(nabto::fingerprint_iam::FingerprintIAMJson::userToJson(*u));
    }
    json_config_save(configFile_, config_);
}

} } } // namespace
