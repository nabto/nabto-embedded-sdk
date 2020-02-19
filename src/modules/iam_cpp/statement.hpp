#pragma once

#include "effect.hpp"
#include "condition.hpp"

#include <set>
#include <vector>
#include <string>

namespace nabto {
namespace iam {

class Statement {
 public:
    Statement(Effect effect, std::set<std::string> actions, std::vector<Condition> conditions)
        : effect_(effect), actions_(actions), conditions_(conditions)
    {
    }

    Effect eval(const std::string& action, const Attributes& attributes) const;

    std::set<std::string> getActions() const
    {
        return actions_;
    }

    std::vector<Condition> getConditions() const
    {
        return conditions_;
    }

    Effect getEffect() const
    {
        return effect_;
    }

 private:
    bool matchActions(const std::string& action) const;

    Condition::Result matchConditions(const Attributes& attributes) const;

    Effect effect_;
    /**
     * List of actions this statement matches
     */
    std::set<std::string> actions_;
    std::vector<Condition> conditions_;
};


} } // namespace
