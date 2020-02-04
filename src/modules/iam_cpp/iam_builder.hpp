#pragma once

#include "conditions.hpp"

namespace nabto {
namespace iam {

class PolicyBuilder {
 public:
    PolicyBuilder() {}
    PolicyBuilder name(const std::string& name)
    {
        name_ = name;
        return *this;
    }
    PolicyBuilder addStatement(const Statement& statement)
    {
        statements_.push_back(statement);
        return *this;
    }
    Policy build() {
        return Policy(name_, statements_);
    }
 private:
    std::string name_;
    std::vector<Statement> statements_;
};

class StatementBuilder {
 public:
    StatementBuilder() {}
    StatementBuilder allow()
    {
        effect_ = Effect::ALLOW;
        return *this;
    }

    StatementBuilder deny()
    {
        effect_ = Effect::DENY;
        return *this;
    }

    StatementBuilder addAction(const std::string& action)
    {
        actions_.insert(action);
        return *this;
    }

    StatementBuilder addAttributeEqualCondition(const std::string& lhs, const std::string& rhs)
    {
        conditions_.push_back(AttributeEqualCondition(lhs, rhs));
        return *this;
    }

    StatementBuilder addCondition(const Condition& condition)
    {
        conditions_.push_back(condition);
        return *this;
    }

    Statement build() {
        return Statement(effect_, actions_, conditions_);
    }

 private:
    Effect effect_;
    std::set<std::string> actions_;
    std::vector<Condition> conditions_;

};

// class RoleBuilder {
//  public:
//     RoleBuilder() {}
//     RoleBuilder name(const std::string& name)
//     {
//         name_ = name;
//         return *this;
//     }

//     RoleBuilder addPolicy(const std::string& policyName)
//     {
//         policies_.insert(policyName);
//         return *this;
//     }

//     Role build()
//     {
//         return Role(name_, policies_);
//     }

//  private:
//     std::string name_;
//     std::set<std::string> policies_;
// };

} } // namespace
