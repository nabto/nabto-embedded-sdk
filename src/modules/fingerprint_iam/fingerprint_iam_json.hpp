#pragma once

#include "fingerprint_iam.hpp"

#include <nlohmann/json.hpp>

namespace nabto {

class FingerprintIAMJson {
 public:


    static bool loadUsers(FingerprintIAM& iam, const nlohmann::json& users);
    static nlohmann::json saveUser(const User& user);
    static bool usersFromJson(FingerprintIAM& iam, const nlohmann::json& json);

    static bool loadRoles(FingerprintIAM& iam, const nlohmann::json& roles);


    static nlohmann::json rolesToJson(const User& user);
    static nlohmann::json fingerprintsToJson(const User& user);

};

} // namespace
