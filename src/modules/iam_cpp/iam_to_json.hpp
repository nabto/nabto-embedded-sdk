#pragma once
#include <nlohmann/json.hpp>

#include "iam.hpp"

namespace nabto {
namespace iam {

class IAMToJson {
 public:
    static std::string usersToJson(const IAM& iam);
    static bool usersFromJson(const std::string& json, std::vector<User>& users);

    static bool policiesFromJson(const std::string& json, std::vector<Policy>& policies);
    static bool rolesFromJson(const std::string& json, std::vector<Role>& roles);
};

} } // namespace
