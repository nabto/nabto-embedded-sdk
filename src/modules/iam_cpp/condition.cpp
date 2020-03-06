#include "condition.hpp"

#include "attributes.hpp"

#include <iostream>

namespace nabto {
namespace iam {

static bool resolveValue(const Attributes& attributes, const std::string& value, std::string& out);

Condition::Result Condition::matches(const Attributes& attributes) const
{
    auto attribute = attributes.get(key_);
    if (!attribute) {
        return Result::NO_MATCH;
    }

    for (auto v : values_) {
        // return true if at least one match exists

        std::string resolvedValue;
        // If the value is a variable we try to resolve it to a string
        // else interpret it as a string.
        if(resolveValue(attributes, v, resolvedValue)) {
            Result r = match(*attribute, resolvedValue);
            if (r == Result::ERROR || r == Result::MATCH) {
                return r;
            }
        }
    }
    return Result::NO_MATCH;

}

Condition::Result Condition::match(const std::string& lhs, const std::string& rhs) const
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
            return Result::ERROR;
    }
}

Condition::Result Condition::stringEquals(const std::string& lhs, const std::string& rhs) const
{
    return status(lhs == rhs);
}

Condition::Result Condition::stringNotEquals(const std::string& lhs, const std::string& rhs) const
{
    return status(lhs != rhs);
}

bool Condition::parseNumeric(const std::string& value, double& out) const
{
    try {
        out = std::stod(value);
        return true;
    } catch (...) {
        std::cerr << "Cannot parse the value: " << value << " as a number" << std::endl;
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
        std::cerr << "Cannot parse the value: " << value << " as a boolean, booleans is either 'true' or 'false'" << std::endl;
        return false;
    }
}

Condition::Result Condition::boolEquals(const std::string& lhs, const std::string& rhs) const
{
    bool lhsBool;
    bool rhsBool;
    if (parseBool(lhs, lhsBool) && parseBool(rhs, rhsBool)) {
        return status(lhsBool == rhsBool);
    }
    return Result::ERROR;
}

Condition::Result Condition::numericCondition(const std::string& lhs, const std::string& rhs) const
{
    double lhsDouble;
    double rhsDouble;
    if (parseNumeric(lhs, lhsDouble) && parseNumeric(rhs, rhsDouble)) {
        switch (operator_) {
            case Condition::Operator::NumericEquals:
                return status(lhsDouble == rhsDouble);
            case Condition::Operator::NumericNotEquals:
                return status(lhsDouble != rhsDouble);
            case Condition::Operator::NumericLessThan:
                return status(lhsDouble < rhsDouble);
            case Condition::Operator::NumericLessThanEquals:
                return status(lhsDouble <= rhsDouble);
            case Condition::Operator::NumericGreaterThan:
                return status(lhsDouble > rhsDouble);
            case Condition::Operator::NumericGreaterThanEquals:
                return status(lhsDouble >= rhsDouble);
            case Condition::Operator::StringEquals:
            case Condition::Operator::StringNotEquals:
            case Condition::Operator::Bool:
                // We should never get here, this silences the compiler.
                return Result::ERROR;
        }
    }
    return Result::ERROR;
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

bool resolveValue(const Attributes& attributes, const std::string& value, std::string& out)
{
    if (value.size() < 3) {
        out = value;
        return true;
    }
    if (value.substr(0,2) == "${" && value.back() == '}') {
        std::string variable = value.substr(2,value.size()-3);
        auto ptr = attributes.get(variable);
        if (ptr) {
            out = *ptr;
            return true;
        }
    } else {
        out = value;
        return true;
    }

    return false;

}


} } // namespace
