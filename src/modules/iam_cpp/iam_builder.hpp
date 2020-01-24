#pragma once
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
        actions_.push_back(action);
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
    std::vector<std::string> actions_;
    std::vector<Condition> conditions_;

};

class ConditionBuilder {
 public:
}

} } // namespace
