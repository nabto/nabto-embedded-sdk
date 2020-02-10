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

bool Statement::matchConditions(const Attributes& attributes) const
{
    for (auto condition : conditions_) {
        // All conditions has to match else it is a no match.
        if (!condition.matches(attributes)) {
            return false;
        }
    }
    return true;
}

Effect Statement::eval(const std::string& action, const Attributes& attributes) const
{
    if (!matchActions(action)) {
        return Effect::NO_MATCH;
    }

    if (!matchConditions(attributes)) {
        return Effect::NO_MATCH;
    }

    // action and conditions matches
    return effect_;
}

} } // namespace
