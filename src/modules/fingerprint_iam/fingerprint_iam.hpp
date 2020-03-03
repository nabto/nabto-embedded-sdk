#pragma once


#include "user.hpp"
#include "subject.hpp"
#include "role.hpp"

#include <nabto/nabto_device.h>

#include <modules/iam_cpp/iam_builder.hpp>

#include <sstream>
#include <functional>
#include <iostream>

namespace nabto {
namespace fingerprint_iam {

class CoapIsPaired;
class CoapPairing;
class CoapPairingPassword;
class CoapPairingButton;
class CoapClientSettings;

class CoapRequestHandler;

class UserBuilder;

class AuthorizationRequestHandler;

class FingerprintIAMChangeListener {
 public:
    virtual void deleteUser(const std::string& userId) = 0;
    virtual void upsertUser(const std::string& userId) = 0;
};

class FingerprintIAM {
 public:
    ~FingerprintIAM();
    FingerprintIAM(NabtoDevice* device);

    /**
     * If enabled the coap endpoint pairing/button is enabled.
     */
    void enableButtonPairing(std::function<void (std::string fingerprint, std::function<void (bool accepted)> cb)> callback);

    /**
     * If enabled the coap endpoint pairing/password is enabled.
     */
    void enablePasswordPairing(const std::string& password);

    /**
     * If enabled it is possible for a client to retrieve client
     * settings from the coap endpoint pairing/client-settings
     */
    void enableClientSettings(const std::string& clientServerUrl, const std::string& clientServerKey);

    /**
     * Remote pairing needs a server connect token.
     */
    void enableRemotePairing(const std::string& serverConnectToken);

    /**
     * Check an action with attributes against the iam system.
     */
    bool checkAccess(NabtoDeviceConnectionRef connectionRef, const std::string& action);
    bool checkAccess(NabtoDeviceConnectionRef connectionRef, const std::string& action, const nabto::iam::Attributes& attributes);
    bool checkAccess(NabtoDeviceConnectionRef connectionRef, const std::string& action,
                     const std::map<std::string, std::string> attributes)
    {
        return checkAccess(connectionRef, action, nabto::iam::Attributes(attributes));
    }

    /**
     * Add a policy to the module.
     */
    void addPolicy(const nabto::iam::Policy& policy);

    /**
     * Add a role to the module.
     */
    bool addRole(const iam::RoleBuilder& roleBuilder);

    /**
     * Add a user to the module
     */
    bool addUser(const UserBuilder& ub);


    /**
     * The client has been granted access with a button press or a password.
     */
    std::shared_ptr<User> pairNewClient(NabtoDeviceCoapRequest* request, const std::string& name);

    void addFingerprintToUser(std::shared_ptr<User> user, const std::string& fingerprint)
    {
        fingerprintToUser_[fingerprint] = user;

        user->setFingerprint(fingerprint);
        if (changeListener_) {
            changeListener_->upsertUser(user->getId());
        }
    }

    bool isPaired(const std::string& fingerprint)
    {
        auto user = findUserByFingerprint(fingerprint);
        return (user != nullptr);
    }


    std::shared_ptr<Role> getRole(const std::string& role)
    {
        auto it = roles_.find(role);
        if (it == roles_.end()) {
            return nullptr;
        }
        return it->second;
    }

    void setUserAttribute(std::shared_ptr<User> user, const std::string& key, const std::string& value);

    std::vector<std::string> getPairingModes();

    void dumpUsers();

    void dumpRoles();

    void dumpPolicies();
    NabtoDevice* getDevice()
    {
        return device_;
    }

    void setChangeListener(std::shared_ptr<FingerprintIAMChangeListener> changeListener) { changeListener_ = changeListener; }

    void removeChangeListener() { changeListener_ = nullptr; }

    std::vector<std::shared_ptr<User> > getUsers() const
    {
        std::vector<std::shared_ptr<User> > users;
        for (auto u : users_) {
            users.push_back(u.second);
        }
        return users;
    }

    std::vector<std::shared_ptr<Role> > getRoles() const
    {
        std::vector<std::shared_ptr<Role> > roles;
        for (auto r : roles_) {
            roles.push_back(r.second);
        }
        return roles;
    }

    std::shared_ptr<User> getUser(const std::string& id)
    {
        auto it = users_.find(id);
        if (it == users_.end()) {
            return nullptr;
        } else {
            return it->second;
        }
    }

    void deleteUser(const std::string& id)
    {
        auto it = users_.find(id);
        if (it != users_.end()) {
            users_.erase(id);
            changeListener_->deleteUser(id);
        }
    }

    bool removeRoleFromUser(const std::string& userId, const std::string& roleId)
    {
        auto user = getUser(userId);
        if (user) {
            user->removeRole(roleId);
            changeListener_->upsertUser(userId);
            return true;
        } else {
            return false;
        }
    }

    bool addRoleToUser(const std::string& userId, const std::string& roleId)
    {
        auto user = getUser(userId);
        auto role = getRole(roleId);
        if (user && role) {
            user->addRole(role);
            changeListener_->upsertUser(userId);
            return true;
        } else {
            return false;
        }
    }

    // return a user if one exists with the given client fingerprint
    std::shared_ptr<User> findUserByCoapRequest(NabtoDeviceCoapRequest* request);

    std::string getFingerprintFromCoapRequest(NabtoDeviceCoapRequest* request);

 private:
    std::shared_ptr<User> findUserByFingerprint(const std::string& fingerprint);
    Subject createUnpairedSubject();
    Subject createSubjectFromUser(const User& user);
    void insertUser(std::shared_ptr<User> user);
    std::string nextUserId();

    std::map<std::string, std::weak_ptr<User> > fingerprintToUser_;
    std::map<std::string, std::shared_ptr<User> > users_;
    std::map<std::string, std::shared_ptr<Role> > roles_;
    std::map<std::string, std::shared_ptr<nabto::iam::Policy> > policies_;

    NabtoDevice* device_;
    std::shared_ptr<FingerprintIAMChangeListener> changeListener_;

    std::unique_ptr<CoapIsPaired> coapIsPaired_;
    std::unique_ptr<CoapPairing> coapPairing_;
    std::unique_ptr<CoapPairingPassword> coapPairingPassword_;
    std::unique_ptr<CoapPairingButton> coapPairingButton_;

    std::unique_ptr<CoapClientSettings> coapClientSettings_;

    std::unique_ptr<CoapRequestHandler> coapListUsers_;
    std::unique_ptr<CoapRequestHandler> coapGetUser_;
    std::unique_ptr<CoapRequestHandler> coapDeleteUser_;
    std::unique_ptr<CoapRequestHandler> coapUsersDeleteRole_;
    std::unique_ptr<CoapRequestHandler> coapUsersAddRole_;
    std::unique_ptr<CoapRequestHandler> coapListRoles_;

    std::unique_ptr<AuthorizationRequestHandler> authorizationRequestHandler_;
};

} } // namespace
