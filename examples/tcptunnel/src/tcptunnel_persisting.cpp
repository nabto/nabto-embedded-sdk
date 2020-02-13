#include "tcptunnel_persisting.hpp"

#include <examples/common/json_config.hpp>
#include <examples/common/random_string.hpp>
#include <modules/fingerprint_iam/fingerprint_iam.hpp>
#include <modules/fingerprint_iam/fingerprint_iam_json.hpp>

namespace nabto {
namespace examples {
namespace tcptunnel {

bool TcpTunnelPersisting::loadUsersIntoIAM(fingerprint_iam::FingerprintIAM& iam)
{
    return fingerprint_iam::FingerprintIAMJson::loadUsersFromJson(iam, config_["Users"]);
}

bool TcpTunnelPersisting::load()
{
    if (!json_config_load(configFile_, config_)) {
        initDefault();
    }
    return true;
}

bool TcpTunnelPersisting::initDefault()
{
    config_["PairingPassword"] = nabto::examples::common::random_string(16);
    save();
    return true;
}

void TcpTunnelPersisting::upsertUser(const fingerprint_iam::User& user)
{
    config_["Users"][user.getId()] = nabto::fingerprint_iam::FingerprintIAMJson::userToJson(user);
    save();
}

void TcpTunnelPersisting::deleteUser(const std::string& id)
{
    config_["Users"].erase(id);
    save();
}

void TcpTunnelPersisting::deleteAllUsers()
{
    config_["Users"].clear();
    save();
}

void TcpTunnelPersisting::save()
{
    json_config_save(configFile_, config_);
}

} } } // namespace
