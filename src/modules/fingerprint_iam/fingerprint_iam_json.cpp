#include "fingerprint_iam_json.hpp"
#include <modules/iam_cpp/iam_to_json.hpp>

#include "user.hpp"
#include "role_builder.hpp"
#include "user_builder.hpp"
#include "fingerprint_iam.hpp"

namespace nabto {
namespace fingerprint_iam {

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

nlohmann::json FingerprintIAMJson::userToJson(const User& user)
{
    nlohmann::json json;
    json["Roles"] = rolesToJson(user);
    json["Attributes"] = iam::IAMToJson::attributesToJson(user.getAttributes());
    json["Fingerprints"] = fingerprintsToJson(user);
    json["Id"] = user.getUserId();
    return json;
}

/**
 * Load user from json
{
  "UserId1": {
    "Roles": ...,
    "Fingerprints": ....,
    "Attributes": ...,
    "Id": ...
  },
  "UserId2": {
    ...
  }
}
*/

static UserBuilder loadUserRoles(const nlohmann::json& roles, UserBuilder ub)
{
    if (roles.is_array()) {
        for (auto r : roles) {
            ub = ub.addRole(r);
        }
    }
    return ub;
}

static UserBuilder loadFingerprints(const nlohmann::json& fingerprints, UserBuilder ub)
{
    if (fingerprints.is_array()) {
        for (auto f : fingerprints) {
            ub = ub.addFingerprint(f);
        }
    }
    return ub;
}

static UserBuilder loadAttributes(const nlohmann::json& attributes, UserBuilder ub)
{
    if (attributes.is_object()) {
        ub.attributes(iam::IAMToJson::attributesFromJson(attributes));
    }
    return ub;
}

bool FingerprintIAMJson::loadUsersFromJson(FingerprintIAM& iam, const nlohmann::json& json)
{
    if (!json.is_object()) {
        return false;
    }

    for (auto it = json.begin(); it != json.end(); it++) {
        UserBuilder ub;
        ub = ub.id(it.key());
        nlohmann::json jsonUser = it.value();

        ub = loadUserRoles(jsonUser["Roles"], ub);
        ub = loadFingerprints(jsonUser["Fingerprints"], ub);
        ub = loadAttributes(jsonUser["Attributes"], ub);

        if (!iam.buildUser(ub)) {
            return false;
        }
    }
    return true;
}

} } // namespace
