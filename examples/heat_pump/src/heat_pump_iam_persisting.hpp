#pragma once

#include <modules/iam_cpp/iam_persisting.hpp>

#include <nlohmann/json.hpp>

namespace nabto {

class HeatPumpIAMPersisting : public iam::IAMPersisting
{
 public:
    HeatPumpIAMPersisting(iam::IAM& iam, const std::string& configFile);

    bool loadUsersFromConfig();
    virtual void loadIAM();
    virtual void upsertUser(const iam::User& user);
    virtual void deleteUser(const std::string& userId);

    virtual void upsertRole() {}
    virtual void removeRole() {}

    virtual void upsertPolicy() {}
    virtual void removePolicy() {}
 private:
    std::string configFile_;
    iam::IAM& iam_;
    nlohmann::json config_;
};

} // namespace
