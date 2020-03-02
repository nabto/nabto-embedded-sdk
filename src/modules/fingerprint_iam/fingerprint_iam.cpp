#include "fingerprint_iam.hpp"
#include "subject.hpp"

#include "coap_is_paired.hpp"
#include "coap_pairing.hpp"
#include "coap_pairing_password.hpp"
#include "coap_pairing_button.hpp"
#include "coap_client_settings.hpp"
#include "coap_list_users.hpp"
#include "coap_get_user.hpp"
#include "coap_delete_user.hpp"
#include "coap_users_delete_role.hpp"
#include "coap_users_add_role.hpp"
#include "coap_list_roles.hpp"
#include "user_builder.hpp"
#include "fingerprint_iam_json.hpp"
#include "authorization_request_handler.hpp"


#include <modules/iam_cpp/decision.hpp>
#include <modules/iam_cpp/iam_to_json.hpp>

#include <cbor.h>
#include <iostream>

namespace nabto {
namespace fingerprint_iam {

FingerprintIAM::~FingerprintIAM()
{
}

FingerprintIAM::FingerprintIAM(NabtoDevice* device)
    : device_(device)
{
    coapIsPaired_ = CoapIsPaired::create(*this, device_);
    coapPairing_ = CoapPairing::create(*this, device_);

    coapListUsers_ = CoapListUsers::create(*this, device_);
    coapGetUser_ = CoapGetUser::create(*this, device_);
    coapDeleteUser_ = CoapDeleteUser::create(*this, device_);
    coapUsersDeleteRole_ = CoapUsersDeleteRole::create(*this, device_);
    coapUsersAddRole_ = CoapUsersAddRole::create(*this, device_);
    coapListRoles_ = CoapListRoles::create(*this, device_);

    authorizationRequestHandler_ = AuthorizationRequestHandler::create(device, *this);
}

void FingerprintIAM::enableButtonPairing(std::function<void (std::string fingerprint, std::function<void (bool accepted)> cb)> callback)
{
    coapPairingButton_ = std::make_unique<CoapPairingButton>(*this, device_);
    coapPairingButton_->init(callback);
}

void FingerprintIAM::enablePasswordPairing(const std::string& password)
{
    coapPairingPassword_ = std::make_unique<CoapPairingPassword>(*this, device_);
    coapPairingPassword_->init(password);
}

void FingerprintIAM::enableClientSettings(const std::string& clientServerUrl, const std::string& clientServerKey)
{
    coapClientSettings_ =  CoapClientSettings::create(*this, device_, clientServerUrl, clientServerKey);

}


bool FingerprintIAM::checkAccess(NabtoDeviceConnectionRef ref, const std::string& action)
{
    nabto::iam::Attributes attributes;
    return checkAccess(ref, action, attributes);
}

static std::string verdictToString(bool verdict)
{
    return verdict ? "granted" : "denied";
}

bool FingerprintIAM::checkAccess(NabtoDeviceConnectionRef ref, const std::string& action, const nabto::iam::Attributes& attributesIn)
{
    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint_full_hex(getDevice(), ref, &fingerprint);
    if (ec) {
        return false;
    }

    auto attributes = attributesIn;


    std::string clientFingerprint(fingerprint);
    nabto_device_string_free(fingerprint);

    std::shared_ptr<User> user = findUserByFingerprint(clientFingerprint);
    bool verdict;
    if (user) {
        attributes.set("Connection:UserId", user->getId());

        auto subject = createSubjectFromUser(*user);
        verdict = nabto::iam::Decision::checkAccess(subject, action, attributes);

        std::cout << "Access " << verdictToString(verdict) << " to the action: " << action << " for the user: " << user->getId() << " on the connection: " << ref << std::endl;
    } else {
        auto subject = createUnpairedSubject();
        verdict = nabto::iam::Decision::checkAccess(subject, action, attributes);
        std::cout << "Access " << verdictToString(verdict) << " to the action: " << action << " for the unpaired connection: " << ref << " with the role: 'Unpaired'" << std::endl;
    }

    return verdict;
}

void FingerprintIAM::addPolicy(const nabto::iam::Policy& policy)
{
    policies_[policy.getId()] = std::make_shared<nabto::iam::Policy>(policy);
}

bool FingerprintIAM::addRole(const iam::RoleBuilder& roleBuilder)
{
    if (roles_.find(roleBuilder.getId()) != roles_.end()) {
        std::cout << "Warning the role " << roleBuilder.getId() << " does already exists" << std::endl;
        return false;
    }
    std::set<std::shared_ptr<nabto::iam::Policy> > policies;
    for (auto policyString : roleBuilder.getPolicies()) {
        auto it = policies_.find(policyString);
        if (it != policies_.end()) {
            policies.insert(it->second);
        } else {
            std::cout << "Warning cannot find policy " << policyString << " for role " << roleBuilder.getId() << std::endl;
            return false;
        }
    }
    roles_[roleBuilder.getId()] = std::make_shared<Role>(roleBuilder.getId(), policies);
    return true;
}

bool FingerprintIAM::addUser(const UserBuilder& ub)
{
    if (users_.find(ub.getId()) != users_.end()) {
        return false;
    }

    std::set<std::shared_ptr<Role> > roles;
    for (auto roleString : ub.getRoles()) {
        auto it = roles_.find(roleString);
        if (it != roles_.end()) {
            roles.insert(it->second);
        } else {
            std::cout << "Cannot add the user " << ub.getId() << " as the role " << roleString << " does not exists" << std::endl;
            return false;
        }
    }

    insertUser(std::make_shared<User>(ub.getId(), roles, ub.getFingerprint(), ub.getServerConnectToken(), ub.getAttributes()));
    return true;
}

void FingerprintIAM::setUserAttribute(std::shared_ptr<User> user, const std::string& key, const std::string& value)
{
    user->setAttribute(key,value);
    if (changeListener_) {
        changeListener_->upsertUser(user->getId());
    }

}

std::vector<std::string> FingerprintIAM::getPairingModes()
{
    std::vector<std::string> modes;
    if (coapPairingPassword_) {
        modes.push_back("Password");
    }
    if (coapPairingButton_) {
        modes.push_back("Button");
    }
    return modes;
}

void FingerprintIAM::dumpUsers()
{
    std::cout << "IAM Users. User Count " << users_.size() << std::endl;
    for (auto u : users_) {
        std::cout << FingerprintIAMJson::userToJson(*u.second) << std::endl;
    }
}

void FingerprintIAM::dumpRoles()
{
    std::cout << "IAM Roles. Role Count " << roles_.size() << std::endl;
    for (auto r : roles_) {
        std::cout << FingerprintIAMJson::roleToJson(*r.second) << std::endl;
    }
}

void FingerprintIAM::dumpPolicies()
{
    std::cout << "IAM Policies. Policies Count " << policies_.size() << std::endl;
    for (auto p : policies_) {
        std::cout << iam::IAMToJson::policyToJson(*p.second) << std::endl;
    }
}

std::string FingerprintIAM::nextUserId()
{
    size_t i;
    for (i = 0;;i++) {
        std::stringstream ss;
        ss << "" << i;
        if (users_.find(ss.str()) == users_.end()) {
            return ss.str();
        }
    }
}

std::shared_ptr<User> FingerprintIAM::pairNewClient(NabtoDeviceCoapRequest* request, const std::string& name)
{
    {
        auto user = findUserByCoapRequest(request);
        if (user) {
            // user is already paired.
            return user;
        }
    }

    auto fingerprint = getFingerprintFromCoapRequest(request);
    if (fingerprint.empty()) {
        return nullptr;
    }

    std::shared_ptr<Role> role;
    if (users_.size() == 0) {
        role = getRole("Admin");
        if (role == nullptr) {
            std::cout << "Warning missing the Role 'Admin' so the user cannot be paired." << std::endl;
            return nullptr;
        }
    } else {
        role = getRole("User");
        if (role == nullptr) {
            std::cout << "Warning missing the Role 'User' so the user cannot be paired." << std::endl;
            return nullptr;
        }
    }

    char* sct;
    NabtoDeviceError ec = nabto_device_create_server_connect_token(getDevice(), &sct);
    if (ec != NABTO_DEVICE_EC_OK) {
        return nullptr;
    }
    std::string serverConnectToken(sct);
    nabto_device_string_free(sct);


    auto user = std::make_shared<User>(nextUserId(), role, fingerprint, serverConnectToken);
    if (!name.empty()) {
        user->setAttribute("Name", name);
    }

    insertUser(user);
    return user;
}


std::shared_ptr<User> FingerprintIAM::findUserByFingerprint(const std::string& fingerprint)
{
    auto it = fingerprintToUser_.find(fingerprint);
    if (it != fingerprintToUser_.end()) {
        return it->second.lock();
    }
    return nullptr;
}

std::string FingerprintIAM::getFingerprintFromCoapRequest(NabtoDeviceCoapRequest* request)
{
    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);

    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint_full_hex(getDevice(), ref, &fingerprint);
    if (ec) {
        return "";
    }
    std::string clientFingerprint(fingerprint);
    nabto_device_string_free(fingerprint);
    return clientFingerprint;
}

std::shared_ptr<User> FingerprintIAM::findUserByCoapRequest(NabtoDeviceCoapRequest* request)
{
    std::string fp = getFingerprintFromCoapRequest(request);
    if (fp.empty()) {
        return nullptr;
    }
    return findUserByFingerprint(fp);
}


Subject FingerprintIAM::createUnpairedSubject()
{
    std::set<std::shared_ptr<nabto::iam::Policy> > policies;
    auto unpairedRole_ = getRole("Unpaired");
    if (unpairedRole_) {
        for (auto policy : unpairedRole_->getPolicies()) {
            policies.insert(policy);
        }
    } else {
        std::cout << "No role 'Unpaired' in the system, the user has no access rights." << std::endl;
    }
    nabto::iam::Attributes attributes;
    return Subject(policies, attributes);
}

Subject FingerprintIAM::createSubjectFromUser(const User& user)
{
    std::set<std::shared_ptr<nabto::iam::Policy> > policies;
    for (auto role : user.getRoles()) {
        for (auto policy : role->getPolicies()) {
            policies.insert(policy);
        }
    }
    return Subject(policies, user.getAttributes());
}

void FingerprintIAM::insertUser(std::shared_ptr<User> user)
{
    users_[user->getId()] = user;
    if (!user->getFingerprint().empty()) {
        fingerprintToUser_[user->getFingerprint()] = user;
    }
    if (changeListener_) {
        changeListener_->upsertUser(user->getId());
    }
}

} } // namespace
