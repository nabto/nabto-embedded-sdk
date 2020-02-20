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
    User(const std::string& id, const std::set<std::shared_ptr<Role> >& roles, const std::set<std::string>& fingerprints, const iam::Attributes& attributes)
        : id_(id), roles_(roles), fingerprints_(fingerprints), attributes_(attributes)
    {
    }
    User(const std::string& id, std::shared_ptr<Role> role)
        : id_(id)
    {
        roles_.insert(role);
    }

    void addFingerprint(const std::string& fingerprint)
    {
        fingerprints_.insert(fingerprint);
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
    std::set<std::string> getFingerprints() const { return fingerprints_; }
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
    std::set<std::string> fingerprints_;
    nabto::iam::Attributes attributes_;
};

} } // namespace
