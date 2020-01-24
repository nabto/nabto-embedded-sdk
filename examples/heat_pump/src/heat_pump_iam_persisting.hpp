#pragma once

#include <iam_persisting.hpp>

namespace nabto {

class HeatPumpIAMPersisting : public IAMPersisting
{
 public:
    virtual void loadIAM();
    virtual void upsertUser(const iam::User& user);
    virtual void deleteUser(const std::string& userId);

    virtual void upsertRole() {}
    virtual void removeRole() {}

    virtual void upsertPolicy() {}
    virtual void removePolicy() {}
 private:
    std::string configFile_;
    iam::Iam& iam_;
};

} // namespace
