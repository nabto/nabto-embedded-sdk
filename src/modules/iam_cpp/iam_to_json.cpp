#include "iam_to_json.hpp"

#include <nlohmann/json.hpp>

namespace nabto {
namespace iam {

std::string IAMToJson::usersToJson(const IAM& iam)
{
    nlohmann::json users;
    return "";
}

static bool toUser(const nlohmann::json& json, const std::string& userId, User& user)
{
    auto roles = json["Roles"];
    auto attributes = json["Attributes"];

    if (roles.is_array()) {
        for (auto role : roles) {
            if (role.is_string()) {
                user.addRole(role);
            }
        }
    }

    if (attributes.is_object()) {
        for (auto it = attributes.begin(); it != attributes.end(); it++) {

            if (role.is_string()) {
                user.addRole(role);
            }
        }
    }

    return true;
}

bool IAMToJson::usersFromJson(const std::string& json, std::vector<User>& users)
{
    auto parsed = nlohmann::json::parse(json);
    for (auto it = parsed.begin(); it != parsed.end(); it++) {
        User user;
        if (!toUser(it.value(), it.key(), user)) {
            return false;
        }
        users.push_back(user);
    }
    return true;
}

bool IAMToJson::policiesFromJson(const std::string& json, std::vector<Policy>& policies)
{
    return false;
}

bool IAMToJson::rolesFromJson(const std::string& json, std::vector<Role>& roles)
{
    return false;
}


} } // namespace
