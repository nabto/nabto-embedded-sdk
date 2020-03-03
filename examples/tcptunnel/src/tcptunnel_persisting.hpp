#pragma once

#include <modules/fingerprint_iam/fingerprint_iam.hpp>

#include <nlohmann/json.hpp>

namespace nabto {
namespace examples {
namespace tcptunnel {

class TcpTunnelPersisting : public fingerprint_iam::FingerprintIAMChangeListener
{
 public:
    TcpTunnelPersisting(const std::string& configFile, fingerprint_iam::FingerprintIAM& iam) : configFile_(configFile), iam_(iam) {}

    virtual ~TcpTunnelPersisting() {}
    virtual void upsertUser(const std::string& userId);
    virtual void deleteUser(const std::string& userId);

    void save();
    bool load();

    bool initDefault();

    std::string getPairingPassword()
    {
        return config_["PairingPassword"].get<std::string>();
    }

    std::string getPairingServerConnectToken()
    {
        return config_["PairingServerConnectToken"].get<std::string>();
    }

 private:
    std::string configFile_;
    fingerprint_iam::FingerprintIAM& iam_;
    nlohmann::json config_;
};

} } } // namespace
