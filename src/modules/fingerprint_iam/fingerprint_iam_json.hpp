#pragma once

namespace nabto {

class FingerprintIAMJson {
 public:
    static bool loadUsers(FingerprintIAM& iam, const nlohmann::json& users);
    static nlohmann::json saveUser(const User& user);

    static bool loadRoles(FingerprintIAM& iam, const nlohmann::json& roles);
};

} // namespace
