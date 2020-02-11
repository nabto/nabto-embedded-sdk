#pragma once

#include "iam_builder.hpp"

#include <nlohmann/json.hpp>

#include <memory>
#include <vector>

namespace nabto {
namespace iam {

class Attributes;
class User;
class Policy;

class IAMToJson {
 public:
    static nlohmann::json attributesToJson(const Attributes& attributes);
    static Attributes attributesFromJson(const nlohmann::json& json);
    static nlohmann::json userToJson(const User& user);
    static bool usersFromJson(const std::string& json, std::vector<User>& users);
    static bool usersFromJson(const nlohmann::json& json, std::vector<User>& users);

    static std::unique_ptr<Policy> policyFromJson(const std::string& json);

    static nlohmann::json policyAsJson(const PolicyBuilder& policyBuilder);
    static nlohmann::json roleAsJson(const RoleBuilder& roleBuilder);

    static RoleBuilder roleFromJson(const nlohmann::json& json);

    static std::vector<RoleBuilder> loadRoles(const nlohmann::json& json);
};

} } // namespace
