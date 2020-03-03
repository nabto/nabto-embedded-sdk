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
    User(const std::string& id, const std::set<std::shared_ptr<Role> >& roles, const std::string& fingerprint, const std::string& serverConnectToken, const iam::Attributes& attributes)
        : id_(id), roles_(roles), fingerprint_(fingerprint), serverConnectToken_(serverConnectToken), attributes_(attributes)
    {
    }

    User(const std::string& id, std::shared_ptr<Role> role, const std::string& fingerprint, const std::string& serverConnectToken)
        : id_(id), fingerprint_(fingerprint), serverConnectToken_(serverConnectToken)
    {
        roles_.insert(role);
    }

    void setFingerprint(const std::string& fingerprint)
    {
        fingerprint_ = fingerprint;
    }



    void setAttribute(const std::string& key, const std::string& value)
    {
        attributes_.set(key, value);
    }

    void removeRole(const std::string& roleId)
    {
        std::shared_ptr<Role> foundRole = getRole(roleId);
        if (foundRole != nullptr) {
            roles_.erase(foundRole);
        }
    }

    void addRole(std::shared_ptr<Role> role)
    {
        roles_.insert(role);
    }

    std::set<std::shared_ptr<Role> > getRoles() const { return roles_; }
    nabto::iam::Attributes getAttributes() const { return attributes_; }
    std::string getId() const { return id_; }
    std::string getFingerprint() const { return fingerprint_; }
    std::string getServerConnectToken() const { return serverConnectToken_; }
 private:

    std::shared_ptr<Role> getRole(const std::string& roleId)
    {
        for (auto r : roles_) {
            if (r->getId() == roleId) {
                return r;
            }
        }
        return nullptr;
    }

    std::string id_;
    std::set<std::shared_ptr<Role> > roles_;
    std::string fingerprint_;
    std::string serverConnectToken_;
    nabto::iam::Attributes attributes_;
};

} } // namespace
