#pragma once

#include "conditions.hpp"
#include "statement.hpp"
#include "effect.hpp"
#include "policy.hpp"

#include <string>
#include <set>
#include <vector>

namespace nabto {
namespace iam {


class StatementBuilder {
 public:
    StatementBuilder(Effect effect) : effect_(effect) {}
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

    Statement build() const {
        return Statement(effect_, actions_, conditions_);
    }

 private:
    Effect effect_;
    std::set<std::string> actions_;
    std::vector<Condition> conditions_;

};

class PolicyBuilder {
 public:
    PolicyBuilder(const std::string& name) : name_(name) {}
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

    PolicyBuilder addStatement(const StatementBuilder& statement)
    {
        statements_.push_back(statement.build());
        return *this;
    }

    Policy build() {
        return Policy(name_, statements_);
    }

    std::string getName() const { return name_; }

    std::vector<Statement> getStatements() const { return statements_; }
 private:
    std::string name_;
    std::vector<Statement> statements_;
};


class RoleBuilder {
 public:
    RoleBuilder(const std::string& name) : name_(name) {}
    RoleBuilder name(const std::string& name)
    {
        name_ = name;
        return *this;
    }

    RoleBuilder addPolicy(const std::string& policyName)
    {
        policies_.insert(policyName);
        return *this;
    }

    std::string getName() const
    {
        return name_;
    }

    std::set<std::string> getPolicies() const
    {
        return policies_;
    }
 private:
    std::string name_;
    std::set<std::string> policies_;
};

} } // namespace
