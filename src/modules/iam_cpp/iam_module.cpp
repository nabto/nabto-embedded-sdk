#include "iam_module.hpp"

namespace nabto {
namespace iam {

bool IAMModule::decice(const std::set<std::string>& policies, const Attributes& subjectAttributes, const std::string& action, const Attributes& resourceAttributes)
{
    Attributes combinedAttributes;
    for (auto a : subjectAttributes) {
        combinedAttributes.insert(a);
    }

    for (auto a : resourceAttributes) {
        combinedAttributes.insert(a);
    }

    bool explicitDeny = false;
    bool explicitAllow = false;

    for (auto p : policies) {
        Effect e = p.eval(action, combinedAttributes);
        if (e == Effect::ALLOW) {
            explicitAllow = true;
        }

        if (e == Effect::DENY) {
            explicitDeny = true;
        }
    }

    if (explicitDeny) {
        return false;
    }

    if (explicitAllow) {
        return true;
    }

    // default deny
    return false;
}

} } // namespace
