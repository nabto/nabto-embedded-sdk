#pragma once

#include <modules/iam_cpp/attributes.hpp>
#include <string>
#include <set>

namespace nabto {
namespace fingerprint_iam {

class UserBuilder
{
 public:
    UserBuilder() {}

    UserBuilder id(const std::string& id)
    {
        id_ = id;
        return *this;
    }

    UserBuilder addFingerprint(const std::string& fingerprint)
    {
        fingerprints_.insert(fingerprint);
        return *this;
    }

    UserBuilder attributes(const iam::Attributes& attributes)
    {
        attributes_ = attributes;
        return *this;
    }

    UserBuilder addRole(const std::string& role)
    {
        roles_.insert(role);
        return *this;
    }

    std::string getId() const { return id_; }
    std::set<std::string> getFingerprints() const { return fingerprints_; }
    std::set<std::string> getRoles() const { return roles_; }
    iam::Attributes getAttributes() const { return attributes_; }

 private:
    std::set<std::string> fingerprints_;
    std::set<std::string> roles_;
    iam::Attributes attributes_;
    std::string id_;
};

} } // namespace
