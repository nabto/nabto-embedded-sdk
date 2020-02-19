#pragma once

#include <string>
#include <set>
#include <memory>
#include <modules/iam_cpp/policy.hpp>

namespace nabto {
namespace fingerprint_iam {

class Role {
 public:
    Role(const std::string& id, const std::set<std::shared_ptr<nabto::iam::Policy> >&  policies)
        : id_(id), policies_(policies)
    {
    }

    std::set<std::shared_ptr<nabto::iam::Policy> > getPolicies() const { return policies_; }
    std::string getId() const { return id_; }
 private:
    std::string id_;
    std::set<std::shared_ptr<nabto::iam::Policy> > policies_;
};

} } // namespace
