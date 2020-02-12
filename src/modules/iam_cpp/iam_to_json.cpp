#include "iam_to_json.hpp"


#include "attributes.hpp"
#include "policy.hpp"
#include "statement.hpp"

#include <nlohmann/json.hpp>

#include <memory>
#include <set>

namespace nabto {
namespace iam {

/**
 * Output
{
  "Foo": "Bar",
  "Baz": "42"
}
*/
nlohmann::json IAMToJson::attributesToJson(const iam::Attributes& attributes)
{
    nlohmann::json json = nlohmann::json::object();
    iam::AttributeMap map = attributes.getMap();
    for (auto a : map) {
        json[a.first] = a.second;
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
                map[key] = value.get<std::string>();
            }
        }
    }
    return Attributes(map);
}

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

std::unique_ptr<Condition> parseCondition(const std::string& op, const nlohmann::json& obj)
{
    if (!obj.is_object()) {
        return nullptr;
    }
    auto it = obj.begin();
    if (it == obj.end()) {
        return nullptr;
    }
    std::vector<std::string> values;
    const std::string key = it.key();
    nlohmann::json v = it.value();
    if (v.is_string()) {
        values.push_back(v.get<std::string>());
    } else if (v.is_array()) {
        for (auto o : v) {
            if (o.is_string()) {
                values.push_back(o.get<std::string>());
            }
        }
    }
    Condition::Operator condOp;
    if (!Condition::operatorFromString(op, condOp)) {
        return nullptr;
    }

    return std::make_unique<Condition>(condOp, key, values);
}

bool loadConditions(const nlohmann::json& statement, std::vector<Condition>& conditions)
{
    if (statement.find("Conditions") == statement.end()) {
        // no conditions is valid
        return true;
    }
    nlohmann::json cs = statement["Conditions"];
    if (!cs.is_array()) {
        return false;
    }
    for (auto c : cs) {
        if (!c.is_object()) {
            return false;
        }
        auto obj = c.begin();
        if (obj == c.end()) {
            return false;
        }

        auto condition = parseCondition(obj.key(), obj.value());
        if (!condition) {
            return false;
        }
        conditions.push_back(*condition);
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

    if (!loadConditions(json, conditions)) {
        return nullptr;
    }

    return std::make_unique<Statement>(effect, actions, conditions);
}

std::unique_ptr<Policy> IAMToJson::policyFromJson(const nlohmann::json& policy)
{
    if (!policy["Name"].is_string()) {
        return nullptr;
    }
    std::string name = policy["Name"].get<std::string>();
    std::vector<Statement> statements;
    if (policy["Statements"].is_array()) {
        for (auto stmt : policy["Statements"]) {
            auto s = loadStatement(stmt);
            if (!s) {
                return nullptr;
            }
            statements.push_back(*s);
        }
    }
    return std::make_unique<Policy>(name, statements);
}

/**
 * Load roles in the format
"Roles" {
  "Role1": {
    "Name": "Role1",
    "Policies": ["p1", "p2"]
  },
  "Role2": {
   ...
  }
}
*/
std::vector<RoleBuilder> IAMToJson::rolesFromJson(const nlohmann::json& roles)
{
    std::vector<RoleBuilder> out;
    for (auto it = roles.begin(); it != roles.end(); it++) {

        RoleBuilder rb(it.key());

        nlohmann::json json = it.value();
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

        out.push_back(rb);
    }
    return out;
}

nlohmann::json IAMToJson::roleToJson(const RoleBuilder& roleBuilder)
{
    nlohmann::json root;
    root["Name"] = roleBuilder.getName();
    root["Policies"] = roleBuilder.getPolicies();
    return root;
}

static nlohmann::json conditionToJson(const Condition& condition)
{
    nlohmann::json root;
    nlohmann::json kv;
    kv[condition.getKey()] = condition.getValues();
    root[Condition::operatorToString(condition.getOperator())] = kv;
    return root;
}

static nlohmann::json statementAsJson(const Statement& statement)
{
    nlohmann::json root;
    if (statement.getEffect() == iam::Effect::ALLOW) {
        root["Effect"] = "Allow";
    } else {
        root["Effect"] = "Deny";
    }

    root["Actions"] = statement.getActions();


    if (!statement.getConditions().empty()) {
        nlohmann::json conditions = nlohmann::json::array();
        for (auto c : statement.getConditions()) {
            conditions.push_back(conditionToJson(c));
        }

        root["Conditions"] = conditions;
    }
    return root;
}

static nlohmann::json statementsAsJson(const std::vector<Statement>& statements)
{
    nlohmann::json out = nlohmann::json::array();
    for (auto s : statements) {
        out.push_back(statementAsJson(s));
    }
    return out;
}

nlohmann::json IAMToJson::policyToJson(const PolicyBuilder& policyBuilder)
{
    nlohmann::json root;

    root["Name"] = policyBuilder.getName();
    root["Statements"] = statementsAsJson(policyBuilder.getStatements());

    return root;
}

nlohmann::json IAMToJson::policyToJson(const Policy& policy)
{
    nlohmann::json root;

    root["Name"] = policy.getName();
    root["Statements"] = statementsAsJson(policy.getStatements());
    return root;
}

} } // namespace
