#include "statement.hpp"

namespace nabto {
namespace iam {

bool Statement::matchActions(const std::string& action) const
{
    for (auto a : actions_) {
        if (action == a) {
            return true;
        }
    }
    return false;
}

Condition::Result Statement::matchConditions(const Attributes& attributes) const
{
    for (auto condition : conditions_) {
        // All conditions has to match else it is a no match.
        Condition::Result r = condition.matches(attributes);
        if (r == Condition::Result::NO_MATCH || r == Condition::Result::ERROR) {
            return r;
        }
    }
    return Condition::Result::MATCH;
}

Effect Statement::eval(const std::string& action, const Attributes& attributes) const
{
    if (!matchActions(action)) {
        return Effect::NO_MATCH;
    }

    Condition::Result r = matchConditions(attributes);
    if (r == Condition::Result::NO_MATCH) {
        return Effect::NO_MATCH;
    }
    if (r == Condition::Result::ERROR) {
        return Effect::ERROR;
    }

    // action and conditions matches
    return effect_;
}

} } // namespace
