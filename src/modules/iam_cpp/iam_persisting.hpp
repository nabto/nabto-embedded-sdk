
#include "iam.hpp"

#include <string>


namespace nabto {
namespace iam {


class IAMPersisting {
 public:
    virtual void loadIam() = 0;

    virtual void deleteUser(const std::string& userId) = 0;
    virtual void upsertUser(const User& user) = 0;

    virtual void deleteRole(const std::string& roleName) = 0;
    virtual void upsertRole(const Role& role) = 0;

    virtual void deletePolicy(const std::string& policyName) = 0;
    virtual void upsertPolicy(const Policy& policy) = 0;
};

} } // namespace
