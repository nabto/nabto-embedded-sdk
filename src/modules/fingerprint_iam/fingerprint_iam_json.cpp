#include "fingerprint_iam_json.hpp"

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
        rb = rb.name(it.key);

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

} // namespace
