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

class UserBuilder;

class AuthorizationRequestHandler;

class FingerprintIAMPersisting {
 public:
    virtual void deleteUser(const std::string& userId) = 0;
    virtual void upsertUser(const User& user) = 0;
};

class FingerprintIAM {
 public:
    ~FingerprintIAM();
    FingerprintIAM(NabtoDevice* device, FingerprintIAMPersisting& persisting);

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
     * Check an action with attributes against the iam system.
     */
    bool checkAccess(NabtoDeviceConnectionRef connectionRef, const std::string& action);
    bool checkAccess(NabtoDeviceConnectionRef connectionRef, const std::string& action, const nabto::iam::Attributes& attributes);

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
    bool pairNewClient(const std::string& fingerprint);

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


    std::shared_ptr<Role> getRole(const std::string& role)
    {
        auto it = roles_.find(role);
        if (it == roles_.end()) {
            return nullptr;
        }
        return it->second;
    }

    std::vector<std::string> getPairingModes();

    void dumpUsers();

    void dumpRoles();

    void dumpPolicies();
    NabtoDevice* getDevice()
    {
        return device_;
    }
 private:
    std::shared_ptr<User> findUserByFingerprint(const std::string& fingerprint);
    Subject createUnpairedSubject();
    Subject createSubjectFromUser(const User& user);
    void insertUser(std::shared_ptr<User> user);
    std::string nextUserId();

    std::map<std::string, std::shared_ptr<User> > fingerprintToUser_;
    std::map<std::string, std::shared_ptr<User> > users_;
    std::map<std::string, std::shared_ptr<Role> > roles_;
    std::map<std::string, std::shared_ptr<nabto::iam::Policy> > policies_;

    NabtoDevice* device_;
    FingerprintIAMPersisting& persisting_;

    std::unique_ptr<CoapIsPaired> coapIsPaired_;
    std::unique_ptr<CoapPairing> coapPairing_;
    std::unique_ptr<CoapPairingPassword> coapPairingPassword_;
    std::unique_ptr<CoapPairingButton> coapPairingButton_;

    std::unique_ptr<CoapClientSettings> coapClientSettings_;

    std::unique_ptr<AuthorizationRequestHandler> authorizationRequestHandler_;
};

} } // namespace
