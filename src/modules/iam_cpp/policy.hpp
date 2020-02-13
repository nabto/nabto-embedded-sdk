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

    Policy(const std::string& id, std::vector<Statement> statements)
        : id_(id), statements_(statements)
    {
    }

    Effect eval(const std::string& action, const Attributes& attributes) const;

    void addStatement(Statement statement)
    {
        statements_.push_back(statement);
    }

    std::string getId() const
    {
        return id_;
    }
    std::vector<Statement> getStatements() const
    {
        return statements_;
    }
 private:
    std::string id_;
    std::vector<Statement> statements_;
};

} } // namespace
