#pragma once

#include <string>
#include <set>
#include <memory>
#include <modules/iam_cpp/policy.hpp>

namespace nabto {
namespace fingerprint_iam {

class Role {
 public:
    Role(const std::string& name, const std::set<std::shared_ptr<nabto::iam::Policy> >&  policies)
        : name_(name), policies_(policies)
    {
    }

    std::set<std::shared_ptr<nabto::iam::Policy> > getPolicies() const { return policies_; }
    std::string getName() const { return name_; }
 private:
    std::string name_;
    std::set<std::shared_ptr<nabto::iam::Policy> > policies_;
};

} } // namespace
