#include "fingerprint_iam.hpp"
#include "subject.hpp"

#include "coap_is_paired.hpp"
#include "coap_pairing.hpp"
#include "coap_pairing_password.hpp"
#include "coap_pairing_button.hpp"
#include "role_builder.hpp"
#include "user_builder.hpp"


#include <modules/iam_cpp/decision.hpp>
#include <modules/iam_cpp/iam.hpp>

#include <cbor.h>
#include <iostream>

namespace nabto {
namespace fingerprint_iam {



FingerprintIAM::~FingerprintIAM()
{

}

FingerprintIAM::FingerprintIAM(NabtoDevice* device, FingerprintIAMPersisting& persisting)
    : device_(device), persisting_(persisting)
{
}

void FingerprintIAM::initCoapHandlers()
{
    coapIsPaired_ = CoapIsPaired::create(*this, device_);
    coapPairing_ = CoapPairing::create(*this, device_);
}

bool FingerprintIAM::checkAccess(NabtoDeviceConnectionRef ref, const std::string& action)
{
    nabto::iam::Attributes attributes;
    return checkAccess(ref, action, attributes);
}

bool FingerprintIAM::checkAccess(NabtoDeviceConnectionRef ref, const std::string& action, const nabto::iam::Attributes& attributes)
{
    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint_hex(getDevice(), ref, &fingerprint);
    if (ec) {
        return false;
    }

    std::string clientFingerprint(fingerprint);
    nabto_device_string_free(fingerprint);

    std::shared_ptr<User> user = findUserByFingerprint(clientFingerprint);
    bool verdict;
    if (user) {
        auto subject = createSubjectFromUser(*user);
        verdict = nabto::iam::Decision::checkAccess(subject, action, attributes);
    } else {
        auto subject = createUnpairedSubject();
        verdict = nabto::iam::Decision::checkAccess(subject, action, attributes);
    }

    if (verdict) {
        std::cout << "Access granted to action: " << action << " For connection with reference: " << ref << std::endl;
    } else {
        std::cout << "Access denied to action: " << action << " For connection with reference: " << ref << std::endl;
    }
    return verdict;
}

Subject FingerprintIAM::createUnpairedSubject()
{
    std::set<std::shared_ptr<nabto::iam::Policy> > policies;
    if (unpairedRole_) {
        for (auto policy : unpairedRole_->getPolicies()) {
            policies.insert(policy);
        }
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

bool FingerprintIAM::addRole(const RoleBuilder& roleBuilder)
{
    if (roles_.find(roleBuilder.getName()) != roles_.end()) {
        return false;
    }
    std::set<std::shared_ptr<nabto::iam::Policy> > policies;
    for (auto policyString : roleBuilder.getPolicies()) {
        auto it = policies_.find(policyString);
        if (it != policies_.end()) {
            policies.insert(it->second);
        } else {
            return false;
        }
    }
    roles_[roleBuilder.getName()] = std::make_shared<Role>(roleBuilder.getName(), policies);
    return true;
}

bool FingerprintIAM::buildUser(const UserBuilder& ub)
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
            return false;
        }
    }

    addUser(std::make_shared<User>(ub.getId(), roles, ub.getFingerprints(), ub.getAttributes()));
    return true;
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

} } // namespace
