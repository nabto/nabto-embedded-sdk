#pragma once

#include <modules/iam_cpp/iam_persisting.hpp>
#include <modules/iam_cpp/iam.hpp>

#include <nlohmann/json.hpp>

namespace nabto {

class HeatPumpPersisting : public iam::AbstractIAMPersisting
{
 public:
    HeatPumpPersisting(iam::IAM& iam, const std::string& configFile);

    bool loadUsersIntoIAM();

    virtual void upsertUser(const iam::User& user);
    virtual void deleteUser(const std::string& userId);

    void save();

    void setProductId(const std::string& productId) {
        config_["ProductId"] = productId;
    }

    std::string getProductId() {
        return config_["ProductId"].get<std::string>();
    }

    void setDeviceId(const std::string& deviceId) {
        config_["DeviceId"] = deviceId;
    }

    std::string getDeviceId() {
        return config_["DeviceId"].get<std::string>();
    }

    void setPrivateKey(const std::string& privateKey)
    {
        config_["PrivateKey"] = privateKey;
    }

    std::string getPrivateKey()
    {
        return config_["PrivateKey"].get<std::string>();
    }

    void setServer(const std::string& server)
    {
        config_["Server"] = server;
    }

    std::string getServer()
    {
        return config_["Server"].get<std::string>();
    }

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

 private:
    std::string configFile_;
    iam::IAM& iam_;
    nlohmann::json config_;
};

} // namespace
