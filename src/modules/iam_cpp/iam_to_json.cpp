#include "iam_to_json.hpp"

#include <nlohmann/json.hpp>

#include <memory>

namespace nabto {
namespace iam {

/**
 * Output
{
  "Foo": "Bar",
  "Baz": 42
}
*/
nlohmann::json IAMToJson::attributesToJson(const iam::Attributes& attributes)
{
    nlohmann::json json;
    iam::AttributeMap map = attributes.getMap();
    for (auto a : map) {
        if (a.second.getType() == AttributeType::STRING) {
            json[a.first] = a.second.getString();
        } else if (a.second.getType() == AttributeType::NUMBER) {
            json[a.first] == a.second.getNumber();
        }
    }
    return json;
}

/**
 * Input format
{
  "Foo": "Bar",
  "Baz": 42
}
 */
Attributes IAMToJson::attributesFromJson(const nlohmann::json& json)
{
    AttributeMap map;
    if (json.is_object()) {
        for (auto it = json.begin(); it != json.end(); it++) {
            std::string key = it.key();
            const nlohmann::json& value = it.value();
            if (value.is_string()) {
                map[key] = Attribute(value.get<std::string>());
            }
            if (value.is_number()) {
                map[key] = Attribute(value.get<int64_t>());
            }
        }
    }
    return Attributes(map);
}

// nlohmann::json IAMToJson::userToJson(const User& user)
// {
//     nlohmann::json jsonUser;

//     nlohmann::json rolesArray = nlohmann::json::array();

//     auto rs = user.getRoles();
//     for (auto r : rs) {
//         rolesArray.push_back(r);
//     }

//     jsonUser["Roles"] = rolesArray;

//     nlohmann::json attributes;

//     auto as = user.getAttributes();
//     for (auto a : as) {
//         if (a.second.getType() == AttributeType::STRING) {
//             attributes[a.first] = a.second.getString();
//         } else if (a.second.getType() == AttributeType::NUMBER) {
//             attributes[a.first] == a.second.getNumber();
//         }
//     }

//     jsonUser["Attributes"] = attributes;

//     return jsonUser;
// }



// static bool toUser(const nlohmann::json& json, User& user)
// {
//     if (json.find("Roles") != json.end()) {
//         auto roles = json["Roles"];

//         if (roles.is_array()) {
//             for (auto role : roles) {
//                 if (role.is_string()) {
//                     user.addRole(role);
//                 }
//             }
//         }
//     }

//     if (json.find("Attributes") != json.end()) {
//         auto attributes = json["Attributes"];
//         if (attributes.is_object()) {
//             for (auto it = attributes.begin(); it != attributes.end(); it++) {
//                 std::string key = it.key();
//                 const nlohmann::json& value = it.value();

//                 if (value.is_string()) {
//                     user.addAttribute(key, Attribute(value.get<std::string>()));
//                 }
//                 if (value.is_number()) {
//                     user.addAttribute(key, Attribute(value.get<int64_t>()));
//                 }
//             }
//         }
//     }

//     return true;
// }

// bool IAMToJson::usersFromJson(const nlohmann::json& parsed, std::vector<User>& users)
// {
//     for (auto it = parsed.begin(); it != parsed.end(); it++) {
//         User user(it.key());
//         if (!toUser(it.value(), user)) {
//             return false;
//         }
//         users.push_back(user);
//     }
//     return true;
// }

// bool IAMToJson::usersFromJson(const std::string& json, std::vector<User>& users)
// {
//     auto parsed = nlohmann::json::parse(json);
//     return usersFromJson(parsed, users);
// }

bool loadEffect(const nlohmann::json& statement, Effect& effect)
{
    if (statement.find("Effect") == statement.end()) {
        return false;
    }
    nlohmann::json e = statement["Effect"];
    if (!e.is_string()) {
        return false;
    }
    std::string s = e.get<std::string>();
    if (s == "Allow") {
        effect = Effect::ALLOW;
        return true;
    }
    if (s == "Deny") {
        effect = Effect::DENY;
        return true;
    }
    return false;
}

bool loadActions(const nlohmann::json& statement, std::set<std::string>& actions)
{
    if (statement.find("Actions") == statement.end()) {
        return false;
    }
    nlohmann::json a = statement["Actions"];
    if (!a.is_array()) {
        return false;
    }
    for (auto action : a) {
        if (action.is_string()) {
            actions.insert(action.get<std::string>());
        }
    }
    return true;
}

std::unique_ptr<Statement> loadStatement(const nlohmann::json& json)
{
    Effect effect;
    std::set<std::string> actions;
    std::vector<Condition> conditions;
    if (!loadEffect(json, effect)) {
        return nullptr;
    }
    if (!loadActions(json, actions)) {
        return nullptr;
    }
    return std::make_unique<Statement>(effect, actions, conditions);
}




std::unique_ptr<Policy> IAMToJson::policyFromJson(const std::string& json)
{
    auto parsed = nlohmann::json::parse(json);
    std::string name = parsed["Name"].get<std::string>();
    std::vector<Statement> statements;
    for (auto stmt : parsed["Statement"]) {
        auto s = loadStatement(stmt);
        if (!s) {
            return nullptr;
        }
        statements.push_back(*s);
    }
    return std::make_unique<Policy>(name, statements);
}

// static bool toRole(const nlohmann::json& json, Role& role)
// {
//     if (json.find("Policies") != json.end()) {
//         nlohmann::json policies = json["Policies"];
//         if (policies.is_array()) {
//             for (auto policy : policies) {
//                 if (policy.is_string()) {
//                     role.addPolicy(policy.get<std::string>());
//                 }
//             }
//         }
//     }
//     return true;
// }

// bool IAMToJson::rolesFromJson(const std::string& json, std::vector<Role>& roles)
// {
//     auto parsed = nlohmann::json::parse(json);
//     for (auto it = parsed.begin(); it != parsed.end(); it++) {
//         Role role(it.key());
//         if (!toRole(it.value(), role)) {
//             return false;
//         }
//         roles.push_back(role);
//     }
//     return true;
// }


} } // namespace
