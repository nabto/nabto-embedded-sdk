#pragma once

#include <nlohmann/json.hpp>

namespace nabto {
namespace fingerprint_iam {

class FingerprintIAM;
class User;

class FingerprintIAMJson {
 public:
    static bool loadUsersFromJson(FingerprintIAM& iam, const nlohmann::json& users);
    static nlohmann::json userToJson(const User& user);
    static bool usersFromJson(FingerprintIAM& iam, const nlohmann::json& json);
    static bool loadRoles(FingerprintIAM& iam, const nlohmann::json& roles);


    static nlohmann::json rolesToJson(const User& user);
    static nlohmann::json fingerprintsToJson(const User& user);

};

} } // namespace
