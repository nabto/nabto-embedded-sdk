#pragma once
#include <nlohmann/json.hpp>

#include "iam.hpp"

#include <memory>

namespace nabto {
namespace iam {

class IAMToJson {
 public:
    static nlohmann::json attributesToJson(const Attributes& attributes);
    static Attributes attributesFromJson(const nlohmann::json& json);
    static nlohmann::json userToJson(const User& user);
    static bool usersFromJson(const std::string& json, std::vector<User>& users);
    static bool usersFromJson(const nlohmann::json& json, std::vector<User>& users);

    static std::unique_ptr<Policy> policyFromJson(const std::string& json);
    static bool rolesFromJson(const std::string& json, std::vector<Role>& roles);
};

} } // namespace
