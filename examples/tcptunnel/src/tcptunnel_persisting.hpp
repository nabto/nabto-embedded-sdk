#pragma once

#include <modules/fingerprint_iam/fingerprint_iam.hpp>
#include <modules/iam_cpp/iam.hpp>

#include <nlohmann/json.hpp>

namespace nabto {
namespace examples {
namespace tcptunnel {

class TcpTunnelPersisting : public fingerprint_iam::FingerprintIAMPersisting
{
 public:
    TcpTunnelPersisting(const std::string& configFile) : configFile_(configFile) {}

    bool loadUsersIntoIAM(fingerprint_iam::FingerprintIAM& iam);

    virtual void upsertUser(const fingerprint_iam::User& user);
    virtual void deleteUser(const std::string& userId);
    virtual void deleteAllUsers();

    void save();
    bool load();

    bool initDefault();

    std::string getPairingPassword()
    {
        return config_["PairingPassword"].get<std::string>();
    }

 private:
    std::string configFile_;
    nlohmann::json config_;
};

} } } // namespace
