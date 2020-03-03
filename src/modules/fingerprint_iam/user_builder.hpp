#pragma once

#include <modules/iam_cpp/attributes.hpp>
#include <string>
#include <set>

namespace nabto {
namespace fingerprint_iam {

class UserBuilder
{
 public:
    UserBuilder(const std::string& id) : id_(id) {}

    UserBuilder setFingerprint(const std::string& fingerprint)
    {
        fingerprint_ = fingerprint;
        return *this;
    }

    UserBuilder setServerConnectToken(const std::string& sct)
    {
        serverConnectToken_ = sct;
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
    std::string getFingerprint() const { return fingerprint_; }
    std::string getServerConnectToken() const { return serverConnectToken_; }
    std::set<std::string> getRoles() const { return roles_; }
    iam::Attributes getAttributes() const { return attributes_; }

 private:
    std::string fingerprint_;
    std::string serverConnectToken_;
    std::set<std::string> roles_;
    iam::Attributes attributes_;
    std::string id_;
};

} } // namespace
