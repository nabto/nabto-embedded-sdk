#pragma once

#include "role.hpp"

#include <modules/iam_cpp/attributes.hpp>


#include <string>
#include <set>
#include <memory>


namespace nabto {
namespace fingerprint_iam {

class User {
 public:
    User(const std::string& userId, const std::set<std::shared_ptr<Role> >& roles, const std::set<std::string>& fingerprints, const iam::Attributes& attributes)
        : userId_(userId), roles_(roles), fingerprints_(fingerprints), attributes_(attributes)
    {
    }
    User(const std::string& userId, std::shared_ptr<Role> role)
        : userId_(userId)
    {
        roles_.insert(role);
    }

    void addFingerprint(const std::string& fingerprint)
    {
        fingerprints_.insert(fingerprint);
    }

    std::set<std::shared_ptr<Role> > getRoles() const { return roles_; }
    nabto::iam::Attributes getAttributes() const { return attributes_; }
    std::string getUserId() const { return userId_; }
    std::set<std::string> getFingerprints() const { return fingerprints_; }
 private:
    std::string userId_;
    std::set<std::shared_ptr<Role> > roles_;
    std::set<std::string> fingerprints_;
    nabto::iam::Attributes attributes_;
};

} } // namespace
