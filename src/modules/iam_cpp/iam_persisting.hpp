#pragma once

#include <string>

namespace nabto {
namespace iam {

class Role;
class User;
class Policy;

class IAMPersisting {
 public:
    virtual void deleteUser(const std::string& userId) = 0;
    virtual void upsertUser(const User& user) = 0;

    virtual void deleteRole(const std::string& roleName) = 0;
    virtual void upsertRole(const Role& role) = 0;

    virtual void deletePolicy(const std::string& policyName) = 0;
    virtual void upsertPolicy(const Policy& policy) = 0;
};

class AbstractIAMPersisting : public IAMPersisting {
 public:
    virtual void deleteUser(const std::string& userId) {}
    virtual void upsertUser(const User& user) {}

    virtual void deleteRole(const std::string& roleName) {}
    virtual void upsertRole(const Role& role) {}

    virtual void deletePolicy(const std::string& policyName) {}
    virtual void upsertPolicy(const Policy& policy) {}
};

} } // namespace
