#pragma once

#include "iam.hpp"
#include "attribute.hpp"
#include "condition.hpp"

#include <string>
#include <map>


namespace nabto {
namespace iam {


class AttributeEqualCondition : public Condition {
 public:
    AttributeEqualCondition(const std::string& lhs, const std::string& rhs)
        : lhs_(lhs), rhs_(rhs)
    {}

    bool matches(const std::map<std::string, Attribute>& attributes)
    {
        auto lhs = attributes.find(lhs_);
        auto rhs = attributes.find(rhs_);
        if (lhs == attributes.end() || rhs == attributes.end()) {
            // at least one of the attributes is missing in the attributes map.
            return false;
        }

        return (lhs->second) == (rhs->second);
    }

 private:
    std::string lhs_;
    std::string rhs_;
};

} }
