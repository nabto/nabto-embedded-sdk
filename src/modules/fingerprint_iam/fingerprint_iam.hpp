#pragma once

#include <nabto/nabto_device.h>

#include <modules/iam_cpp/iam.hpp>

#include <sstream>

namespace nabto {

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

class FingerprintIAMSubject : public nabto::iam::Subject {
 public:
    FingerprintIAMSubject(const std::set<std::shared_ptr<nabto::iam::Policy> >& policies, const nabto::iam::Attributes& attributes)
        : policies_(policies), attributes_(attributes)
    {
    }
    virtual std::set<std::shared_ptr<nabto::iam::Policy> > getPolicies() const
    {
        return policies_;
    }
    virtual nabto::iam::Attributes getAttributes() const
    {
        return attributes_;
    }
 private:
    std::set<std::shared_ptr<nabto::iam::Policy> > policies_;
    nabto::iam::Attributes attributes_;
};

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

class User {
 public:
    User(const std::string& userId, std::shared_ptr<Role> role)
    {

    }
    std::set<std::shared_ptr<Role> > getRoles() const { return roles_; }
    nabto::iam::Attributes getAttributes() const { return attributes_; }
    std::string getUserId() const { return userId_; }
    std::set<std::string> getFingerprints() const { return fingerprints_; }
 private:
    std::string userId_;
    nabto::iam::Attributes attributes_;
    std::set<std::shared_ptr<Role> > roles_;
    std::set<std::string> fingerprints_;
};

class FingerprintIAMPersisting {
 public:
    virtual void deleteUser(const std::string& userId) = 0;
    virtual void upsertUser(const User& user) = 0;
};

class FingerprintIAM {
 public:
    FingerprintIAM(NabtoDevice* device, FingerprintIAMPersisting& persisting);
    bool checkAccess(NabtoDeviceConnectionRef connectionRef, const std::string& action);
    bool checkAccess(NabtoDeviceConnectionRef connectionRef, const std::string& action, const nabto::iam::Attributes& attributes);

    void initCoapHandlers();

    FingerprintIAMSubject unpairedSubject();

    FingerprintIAMSubject createSubjectFromUser(const User& user);

    void addPolicy(const nabto::iam::Policy& policy)
    {
        policies_[policy.getName()] = std::make_shared<nabto::iam::Policy>(policy);
    }

    bool addRole(const RoleBuilder& roleBuilder)
    {
        if (roles_.find(roleBuilder.getName()) != roles_.end()) {
            return false;
        }
        std::set<std::shared_ptr<nabto::iam::Policy> > policies;
        for (auto policyString : roleBuilder.getPolicies()) {
            auto p = policies_[policyString];
            if (p) {
                policies.insert(p);
            } else {
                return false;
            }
        }
        roles_[roleBuilder.getName()] = std::make_shared<Role>(roleBuilder.getName(), policies);
        return true;
    }

    std::shared_ptr<User> findUserByFingerprint(const std::string& fingerprint)
    {
        auto it = fingerprintToUser_.find(fingerprint);
        if (it != fingerprintToUser_.end()) {
            return it->second;
        }
        return nullptr;
    }

    NabtoDevice* getDevice()
    {
        return device_;
    }

    /**
     * The client has been granted access with a button press or a password.
     */
    bool pairNewClient(const std::string& fingerprint)
    {
        {
            auto user = findUserByFingerprint(fingerprint);
            if (user) {
                // user is already paired.
                return true;
            }
        }

        if (users_.size() == 0) {
            if (!adminRole_) {
                return false;
            }
            auto user = std::make_shared<User>("admin", adminRole_);
            addUser(user);
            addFingerprintToUser(user, fingerprint);
            return true;
        } else {
            if (!guestRole_) {
                return false;
            }
            std::stringstream ss;
            ss << "guest-" << (users_.size() + 1);
            auto user = std::make_shared<User>(ss.str(), guestRole_);
            addUser(user);
            addFingerprintToUser(user, fingerprint);
            return true;

        }
    }

    void addUser(std::shared_ptr<User> user)
    {
        users_[user->getUserId()] = user;
    }

    void addFingerprintToUser(std::shared_ptr<User> user, const std::string& fingerprint)
    {
        fingerprintToUser_[fingerprint] = user;
    }

    bool isPaired(const std::string& fingerprint)
    {
        auto user = findUserByFingerprint(fingerprint);
        return (user != nullptr);
    }


 private:
    std::map<std::string, std::shared_ptr<User> > fingerprintToUser_;
    std::map<std::string, std::shared_ptr<User> > users_;
    std::map<std::string, std::shared_ptr<Role> > roles_;
    std::map<std::string, std::shared_ptr<nabto::iam::Policy> > policies_;

    std::shared_ptr<Role> unpairedRole_;
    std::shared_ptr<Role> adminRole_;
    std::shared_ptr<Role> guestRole_;

    NabtoDevice* device_;
    FingerprintIAMPersisting& persisting_;
};

} // namespace
