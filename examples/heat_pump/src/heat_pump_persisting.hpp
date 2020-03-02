#pragma once

#include <modules/fingerprint_iam/fingerprint_iam.hpp>

#include <nlohmann/json.hpp>

namespace nabto {
namespace examples {
namespace heat_pump {

class HeatPumpPersisting : public fingerprint_iam::FingerprintIAMChangeListener
{
 public:
    HeatPumpPersisting(const std::string& configFile, fingerprint_iam::FingerprintIAM& iam);
    virtual ~HeatPumpPersisting() {}


    virtual void upsertUser(const std::string& id);
    virtual void deleteUser(const std::string& id);

    void save();
    bool load();


    bool initDefault();

    void setHeatPumpMode(const std::string& mode)
    {
        config_["HeatPump"]["Mode"] = mode;
    }

    std::string getHeatPumpMode()
    {
        return config_["HeatPump"]["Mode"].get<std::string>();
    }

    void setHeatPumpPower(bool on)
    {
        config_["HeatPump"]["Power"] = on;
    }

    bool getHeatPumpPower()
    {
        return config_["HeatPump"]["Power"].get<bool>();
    }

    void setHeatPumpTarget(double target)
    {
        config_["HeatPump"]["Target"] = target;
    }

    double getHeatPumpTarget()
    {
        return config_["HeatPump"]["Target"].get<double>();
    }

    std::string getPairingPassword()
    {
        return config_["PairingPassword"].get<std::string>();
    }

    std::string getPairingServerConnectToken()
    {
        return config_["PairingServerConnectToken"].get<std::string>();
    }
 private:
    std::map<std::string, nlohmann::json> users_;
    std::string configFile_;
    fingerprint_iam::FingerprintIAM& iam_;
    nlohmann::json config_;
};

} } } // namespace
