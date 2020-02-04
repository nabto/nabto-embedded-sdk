#include "fingerprint_iam.hpp"

#include <modules/iam_cpp/iam.hpp>

#include <cbor.h>

namespace nabto {

FingerprintIAM::FingerprintIAM(NabtoDevice* device, FingerprintIAMPersisting& persisting)
    : device_(device), persisting_(persisting)
{

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
    if (user) {
        auto subject = createSubjectFromUser(*user);
        return nabto::iam::IamPdp::checkAccess(subject, action, attributes);
    } else {
        auto subject = unpairedSubject();
        return nabto::iam::IamPdp::checkAccess(subject, action, attributes);
    }
    // Find paired user or use the unpaired role.
}

nabto::FingerprintIAMSubject FingerprintIAM::unpairedSubject()
{
    std::set<std::shared_ptr<nabto::iam::Policy> > policies;
    if (unpairedRole_) {
        for (auto policy : unpairedRole_->getPolicies()) {
            policies.insert(policy);
        }
    }
    nabto::iam::Attributes attributes;
    return FingerprintIAMSubject(policies, attributes);
}

nabto::FingerprintIAMSubject FingerprintIAM::createSubjectFromUser(const User& user)
{
    std::set<std::shared_ptr<nabto::iam::Policy> > policies;
    for (auto role : user.getRoles()) {
        for (auto policy : role->getPolicies()) {
            policies.insert(policy);
        }
    }
    return FingerprintIAMSubject(policies, user.getAttributes());
}

void FingerprintIAM::initCoapHandlers()
{

}

} // namespace
