#pragma once

#include "statement.hpp"
#include "effect.hpp"

#include <string>
#include <vector>

namespace nabto {
namespace iam {

class Policy {
 public:

    Policy() {}

    Policy(const std::string& name, std::vector<Statement> statements)
        : name_(name), statements_(statements)
    {
    }

    Effect eval(const std::string& action, const Attributes& attributes) const;

    void addStatement(Statement statement)
    {
        statements_.push_back(statement);
    }

    void setVersion(int version)
    {
        version_ = version;
    }

    void setName(const std::string& name)
    {
        name_ = name;
    }

    std::string getName() const
    {
        return name_;
    }
    std::vector<Statement> getStatements() const
    {
        return statements_;
    }
 private:
    int version_;
    std::string name_;
    std::vector<Statement> statements_;
};

} } // namespace
