#pragma once

#include "iam_builder.hpp"

#include <nlohmann/json.hpp>

#include <memory>
#include <vector>

namespace nabto {
namespace iam {

class Attributes;
class Policy;

class IAMToJson {
 public:
    static nlohmann::json attributesToJson(const Attributes& attributes);
    static Attributes attributesFromJson(const nlohmann::json& json);

    static std::unique_ptr<Policy> policyFromJson(const nlohmann::json& policy);
    static nlohmann::json policyToJson(const PolicyBuilder& policyBuilder);

    static nlohmann::json roleToJson(const RoleBuilder& roleBuilder);
    static RoleBuilder roleFromJson(const nlohmann::json& json);
    static std::vector<RoleBuilder> rolesFromJson(const nlohmann::json& json);
};

} } // namespace
