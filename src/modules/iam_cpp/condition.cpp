#include "condition.hpp"

#include "attributes.hpp"

namespace nabto {
namespace iam {

bool Condition::matches(const Attributes& attributes) const
{
    auto attribute = attributes.get(key_);
    if (!attribute) {
        return false;
    }

    for (auto v : values_) {
        // return true if at least one match exists
        if (match(*attribute, v)) {
            return true;
        }
    }
    return false;

}

bool Condition::match(const std::string& lhs, const std::string& rhs) const
{
    switch (operator_) {
        case Condition::Operator::StringEquals:
            return stringEquals(lhs, rhs);
        case Condition::Operator::StringNotEquals:
            return stringNotEquals(lhs, rhs);
        case Condition::Operator::NumericEquals:
        case Condition::Operator::NumericNotEquals:
        case Condition::Operator::NumericLessThan:
        case Condition::Operator::NumericLessThanEquals:
        case Condition::Operator::NumericGreaterThan:
        case Condition::Operator::NumericGreaterThanEquals:
            return numericCondition(lhs, rhs);
        case Condition::Operator::Bool:
            return boolEquals(lhs, rhs);
        default:
            return false;
    }
}

bool Condition::stringEquals(const std::string& lhs, const std::string& rhs) const
{
    return lhs == rhs;
}

bool Condition::stringNotEquals(const std::string& lhs, const std::string& rhs) const
{
    return lhs != rhs;
}

bool Condition::parseNumeric(const std::string& value, double& out) const
{
    try {
        out = std::stod(value);
        return true;
    } catch (...) {
        return false;
    }
}

bool Condition::parseBool(const std::string& value, bool& out) const
{
    if (value == "true") {
        out = true;
        return true;
    } else if (value == "false") {
        out = false;
        return true;
    } else {
        return false;
    }
}

bool Condition::boolEquals(const std::string& lhs, const std::string& rhs) const
{
    bool lhsBool;
    bool rhsBool;
    if (parseBool(lhs, lhsBool) && parseBool(rhs, rhsBool)) {
        return (lhsBool == rhsBool);
    }
    return false;
}

bool Condition::numericCondition(const std::string& lhs, const std::string& rhs) const
{
    double lhsDouble;
    double rhsDouble;
    if (parseNumeric(lhs, lhsDouble) && parseNumeric(rhs, rhsDouble)) {
        switch (operator_) {
            case Condition::Operator::NumericEquals:
                return (lhsDouble == rhsDouble);
            case Condition::Operator::NumericNotEquals:
                return (lhsDouble != rhsDouble);
            case Condition::Operator::NumericLessThan:
                return (lhsDouble < rhsDouble);
            case Condition::Operator::NumericLessThanEquals:
                return (lhsDouble <= rhsDouble);
            case Condition::Operator::NumericGreaterThan:
                return (lhsDouble > rhsDouble);
            case Condition::Operator::NumericGreaterThanEquals:
                return (lhsDouble >= rhsDouble);
            default:
                return false;
        }
    }
    return false;
}

bool Condition::operatorFromString(const std::string& str, Condition::Operator& op)
{
    if (str == "StringEquals") {
        op = Condition::Operator::StringEquals;
    } else if (str == "StringNotEquals") {
        op = Condition::Operator::StringNotEquals;
    } else if (str == "NumericEquals") {
        op = Condition::Operator::NumericEquals;
    } else if (str == "NumericNotEquals") {
        op = Condition::Operator::NumericNotEquals;
    } else if (str == "NumericLessThan") {
        op = Condition::Operator::NumericLessThan;
    } else if (str == "NumericLessThanEquals") {
        op = Condition::Operator::NumericLessThanEquals;
    } else if (str == "NumericGreaterThan") {
        op = Condition::Operator::NumericGreaterThan;
    } else if (str == "NumericGreaterThanEquals") {
        op = Condition::Operator::NumericGreaterThanEquals;
    } else if (str == "Bool") {
        op = Condition::Operator::Bool;
    } else {
        return false;
    }
    return true;
}

std::string Condition::operatorToString(const Condition::Operator& op)
{
    switch (op) {
        case Condition::Operator::StringEquals: return "StringEquals";
        case Condition::Operator::StringNotEquals: return "StringNotEquals";
        case Condition::Operator::NumericEquals: return "NumericEquals";
        case Condition::Operator::NumericNotEquals: return "NumericNotEquals";
        case Condition::Operator::NumericLessThan: return "NumericLessThan";
        case Condition::Operator::NumericLessThanEquals: return "NumericLessThanEquals";
        case Condition::Operator::NumericGreaterThan: return "NumericGreaterThan";
        case Condition::Operator::NumericGreaterThanEquals: return "NumericGreaterThanEquals";
        case Condition::Operator::Bool: return "Bool";
        default: return "";
    }
}

} } // namespace
