#include "fingerprint_iam_json.hpp"
#include <modules/iam_cpp/iam_to_json.hpp>

namespace nabto {

/**
"Roles": {
  "Admin": {
    "Policies": ["p1", "p2"]
  }
}
*/



bool FingerprintIAMJson::loadRoles(FingerprintIAM& iam, const nlohmann::json& roles)
{
    for (auto it = roles.begin(); it != roles.end(); it++) {

        RoleBuilder rb;
        rb = rb.name(it.key());

        nlohmann::json json = it.value();
        if (json.find("Policies") != json.end()) {
            nlohmann::json policies = json["Policies"];
            if (policies.is_array()) {
                for (auto policy : policies) {
                    if (policy.is_string()) {
                        rb = rb.addPolicy(policy.get<std::string>());
                    }
                }
            }
        }

        if (!iam.addRole(rb)) {
            return false;
        }
    }
    return true;
}

nlohmann::json FingerprintIAMJson::rolesToJson(const User& user)
{
    nlohmann::json roles = nlohmann::json::array();
    for (auto r : user.getRoles())
    {
        roles.push_back(r->getName());
    }
    return roles;
}

nlohmann::json FingerprintIAMJson::fingerprintsToJson(const User& user)
{
    nlohmann::json fingerprints = nlohmann::json::array();

    for (auto f : user.getFingerprints()) {
        fingerprints.push_back(f);
    }
    return fingerprints;
}

nlohmann::json FingerprintIAMJson::saveUser(const User& user)
{
    nlohmann::json json;
    json["Roles"] = rolesToJson(user);
    json["Attributes"] = iam::IAMToJson::attributesToJson(user.getAttributes());
    json["Fingerprints"] = fingerprintsToJson(user);
    json["Id"] = user.getUserId();
    return json;
}

bool FingerprintIAMJson::usersFromJson(FingerprintIAM& iam, const nlohmann::json& json)
{
    return false;
}

} // namespace
