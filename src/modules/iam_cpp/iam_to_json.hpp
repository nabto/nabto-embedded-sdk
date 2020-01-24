#pragma once
#include <nlohmann/json.hpp>

#include "iam.hpp"

#include <memory>

namespace nabto {
namespace iam {

class IAMToJson {
 public:
    static std::string usersToJson(const IAM& iam);
    static bool usersFromJson(const std::string& json, std::vector<User>& users);

    static std::unique_ptr<Policy> policyFromJson(const std::string& json);
    static bool rolesFromJson(const std::string& json, std::vector<Role>& roles);
};

} } // namespace
