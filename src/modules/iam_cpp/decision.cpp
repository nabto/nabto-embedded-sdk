#include "decision.hpp"

#include "subject.hpp"
#include "attributes.hpp"
#include "effect.hpp"
#include "policy.hpp"

#include <iostream>

namespace nabto {
namespace iam {

bool Decision::checkAccess(const Subject& subject, const std::string& action, const Attributes& attributes)
{
    Attributes attrs;
    attrs.merge(attributes);
    attrs.merge(subject.getAttributes());

    nabto::iam::Effect result = nabto::iam::Effect::NO_MATCH;

    for (auto policy : subject.getPolicies()) {
        nabto::iam::Effect effect = policy->eval(action, attrs);
        if (effect == Effect::ERROR) {
            std::cerr << "evaluating the policy: " << policy->getId() << " resulted in an error, denying the access request" << std::endl;
            return false;
        }
        if (effect == Effect::DENY) {
            return false;
        }
        if (effect == Effect::ALLOW) {
            result = Effect::ALLOW;
        }
    }
    if (result == Effect::ALLOW) {
        return true;
    }
    return false;
}

} } // namespace
