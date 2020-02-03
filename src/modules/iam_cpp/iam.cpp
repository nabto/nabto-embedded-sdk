#pragma once

namespace nabto {
namespace iam {

Statement::matches()
{

}

Effect Policy::eval(const std::string& action, const Attributes& attributes)
{
    Effect decistion = Effect::NO_MATCH;
    for (auto stmt : statements_) {
        Effect effect = stmt.eval(action, attributes);
        if (effect != Effect::NO_MATCH) {
            decision = effect;
        }
    }
    return decision;
}

bool Statement::matchActions(const std::string& action)
{
    for (auto a : actions_) {
        if (action == a) {
            return true;
        }
    }
    return false;
}

bool Statement::matchCondition(const Condition& condition, const Attributes& attributes)
{
    return condition.matches(attributes);
}

bool Statement::matchConditions(const Attributes& attributes)
{
    for (auto condition : conditions_) {
        // All conditions has to match else it is a no match.
        if (!condition.matches(attributes)) {
            return false;
        }
    }
}

Effect Statement::eval(const std::string& action, const Attributes& attributes)
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

bool IAM::checkIamAccess(const Subject& subject, const std::string& action, const Attributes& attributes)
{

}

} } // namespace
