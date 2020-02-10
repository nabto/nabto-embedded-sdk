#pragma once

#include <string>
#include <set>

namespace nabto {
namespace fingerprint_iam {

class RoleBuilder {
 public:
    RoleBuilder() {}
    RoleBuilder name(const std::string& name)
    {
        name_ = name;
        return *this;
    }

    RoleBuilder addPolicy(const std::string& policy)
    {
        policies_.insert(policy);
        return *this;
    }

    std::string getName() const { return name_; }
    std::set<std::string> getPolicies() const { return policies_; }
 private:
    std::set<std::string> policies_;
    std::string name_;
};

} } // namespace
