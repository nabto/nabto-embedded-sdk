#pragma once

#include "iam.hpp"

namespace nabto {
namespace iam {


class StringEqualCondition {
 public:
    bool matches(const std::map<std::string, Attribute>& attributes)
    {
        std::string lhs;
        std::string rhs;
        if (lhs_.resolve(attributes, lhs) && rhs_.resolve(attributes, rhs)) {
            return lhs == rhs;
        } else {
            return false;
        }
    }
 private:
    StringArgument lhs_;
    StringArgument rhs_;
};

class NumberEqualCondition {
 public:
    bool matches(const std::map<std::string, Attribute>& attributes)
    {
        int64_t lhs;
        int64_t rhs;
        if (lhs_.resolve(attributes, lhs) == rhs_.resolve(attributes, rhs)) {
            return lhs == rhs;
        } else {
            return false;
        }
    }
 private:
    NumberArgument lhs_;
    NumberArgument rhs_;
};


} }
