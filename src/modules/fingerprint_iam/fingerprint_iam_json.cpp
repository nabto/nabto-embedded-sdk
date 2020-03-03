#include "fingerprint_iam_json.hpp"
#include <modules/iam_cpp/iam_to_json.hpp>

#include "user.hpp"
#include "role.hpp"
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
    std::vector<iam::RoleBuilder> rbs = iam::IAMToJson::rolesFromJson(roles);
    for (auto& rb : rbs) {
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
        roles.push_back(r->getId());
    }
    return roles;
}

nlohmann::json FingerprintIAMJson::userToJson(const User& user)
{
    nlohmann::json json;
    json["Roles"] = rolesToJson(user);
    if (!user.getAttributes().empty()) {
        json["Attributes"] = iam::IAMToJson::attributesToJson(user.getAttributes());
    }
    if (!user.getFingerprint().empty()) {
        json["Fingerprint"] = user.getFingerprint();
    }
    if (!user.getServerConnectToken().empty()) {
        json["ServerConnectToken"] = user.getServerConnectToken();
    }
    json["Id"] = user.getId();
    return json;
}

/**
 * Load user from json
[
  {
    "UserId1": ...,
    "Roles": ...,
    "Fingerprint": ....,
    "
    "Attributes": ...,
    "Id": ...
  }
]
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

static UserBuilder loadFingerprint(const nlohmann::json& fingerprint, UserBuilder ub)
{
    if (fingerprint.is_string()) {
        ub = ub.setFingerprint(fingerprint.get<std::string>());
    }
    return ub;
}
static UserBuilder loadServerConnectToken(const nlohmann::json& sct, UserBuilder ub)
{
    if (sct.is_string()) {
        ub = ub.setServerConnectToken(sct.get<std::string>());
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
    if (!json.is_array()) {
        return false;
    }

    for (auto user : json) {
        nlohmann::json id = user["Id"];
        if (id.is_string()) {
            UserBuilder ub(id.get<std::string>());

            ub = loadUserRoles(user["Roles"], ub);
            ub = loadFingerprint(user["Fingerprint"], ub);
            ub = loadServerConnectToken(user["ServerConnectToken"], ub);
            ub = loadAttributes(user["Attributes"], ub);

            if (!iam.addUser(ub)) {
                return false;
            }
        }
    }
    return true;
}

nlohmann::json FingerprintIAMJson::roleToJson(const Role& role)
{
    nlohmann::json json;

    json["Id"] = role.getId();
    nlohmann::json policies = nlohmann::json::array();
    for (auto p : role.getPolicies()) {
        policies.push_back(p->getId());
    }
    json["Policies"] = policies;
    return json;
}

} } // namespace
