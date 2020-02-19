#include "policy.hpp"

namespace nabto {
namespace iam {

Effect Policy::eval(const std::string& action, const Attributes& attributes) const
{
    Effect decision = Effect::NO_MATCH;
    for (auto stmt : statements_) {
        Effect effect = stmt.eval(action, attributes);
        if (effect == Effect::ERROR || effect == Effect::DENY) {
            return effect;
        }
        if (effect == Effect::ALLOW) {
            decision = effect;
        }
    }
    return decision;
}

} } // namespace
