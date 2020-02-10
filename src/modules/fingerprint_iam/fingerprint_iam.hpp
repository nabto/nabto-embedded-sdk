#pragma once


#include "user.hpp"
#include "subject.hpp"
#include "role.hpp"

#include <nabto/nabto_device.h>

#include <modules/iam_cpp/iam.hpp>

#include <sstream>
#include <functional>

namespace nabto {
namespace fingerprint_iam {

class CoapIsPaired;
class CoapPairing;
class CoapPairingPassword;
class CoapPairingButton;

class RoleBuilder;
class UserBuilder;

class FingerprintIAMPersisting {
 public:
    virtual void deleteUser(const std::string& userId) = 0;
    virtual void upsertUser(const User& user) = 0;
};

class FingerprintIAM {
 public:
    ~FingerprintIAM();
    FingerprintIAM(NabtoDevice* device, FingerprintIAMPersisting& persisting);
    bool checkAccess(NabtoDeviceConnectionRef connectionRef, const std::string& action);
    bool checkAccess(NabtoDeviceConnectionRef connectionRef, const std::string& action, const nabto::iam::Attributes& attributes);

    void initCoapHandlers();


    void addPolicy(const nabto::iam::Policy& policy)
    {
        policies_[policy.getName()] = std::make_shared<nabto::iam::Policy>(policy);
    }

    bool addRole(const RoleBuilder& roleBuilder);

    bool buildUser(const UserBuilder& ub);

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
            if (!ownerRole_) {
                return false;
            }
            auto user = std::make_shared<User>("owner", ownerRole_);
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
        for (auto fp : user->getFingerprints()) {
            fingerprintToUser_[fp] = user;
        }
        persisting_.upsertUser(*user);
    }

    void addFingerprintToUser(std::shared_ptr<User> user, const std::string& fingerprint)
    {
        fingerprintToUser_[fingerprint] = user;

        user->addFingerprint(fingerprint);
        persisting_.upsertUser(*user);
    }

    bool isPaired(const std::string& fingerprint)
    {
        auto user = findUserByFingerprint(fingerprint);
        return (user != nullptr);
    }

    void enableButtonPairing(std::function<void (std::string fingerprint, std::function<void (bool accepted)> cb)> callback);
    void enablePasswordPairing(const std::string& password);

    std::shared_ptr<Role> getRole(const std::string& role)
    {
        auto it = roles_.find(role);
        if (it == roles_.end()) {
            return nullptr;
        }
        return it->second;
    }

    bool setUnpairedRole(const std::string& role)
    {
        unpairedRole_ = getRole(role);
        return (unpairedRole_ != nullptr);
    }

    bool setOwnerRole(const std::string& role)
    {
        ownerRole_ = getRole(role);
        return (ownerRole_ != nullptr);
    }

    bool setGuestRole(const std::string& role)
    {
        guestRole_ = getRole(role);
        return (guestRole_ != nullptr);
    }

    std::vector<std::string> getPairingModes();

 private:

    Subject createUnpairedSubject();
    Subject createSubjectFromUser(const User& user);

    std::map<std::string, std::shared_ptr<User> > fingerprintToUser_;
    std::map<std::string, std::shared_ptr<User> > users_;
    std::map<std::string, std::shared_ptr<Role> > roles_;
    std::map<std::string, std::shared_ptr<nabto::iam::Policy> > policies_;

    std::shared_ptr<Role> unpairedRole_;
    std::shared_ptr<Role> ownerRole_;
    std::shared_ptr<Role> guestRole_;

    NabtoDevice* device_;
    FingerprintIAMPersisting& persisting_;

    std::unique_ptr<CoapIsPaired> coapIsPaired_;
    std::unique_ptr<CoapPairing> coapPairing_;
    std::unique_ptr<CoapPairingPassword> coapPairingPassword_;
    std::unique_ptr<CoapPairingButton> coapPairingButton_;
};

} } // namespace
