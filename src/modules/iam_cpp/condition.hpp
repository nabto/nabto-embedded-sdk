#pragma once

#include <vector>
#include <string>

namespace nabto {
namespace iam {

class Attributes;

/**
 * Generic encapsulation of
 * { "Operator": { "Key" : [ "Value1", "Value2" ] } }
 */
class Condition {
 public:

    enum class Operator {
        StringEquals,
        StringNotEquals,
        NumericEquals,
        NumericNotEquals,
        NumericLessThan,
        NumericLessThanEquals,
        NumericGreaterThan,
        NumericGreaterThanEquals,
        Bool
    };

    Condition(Operator op, const std::string& key, const std::vector<std::string>& values)
        : operator_(op), key_(key), values_(values)
    {
    }
    virtual ~Condition() {}
    virtual bool matches(const Attributes& attributes) const;

    static bool operatorFromString(const std::string& str, Condition::Operator& op);

    static std::string operatorToString(const Condition::Operator& op);

    std::string getKey() const
    {
        return key_;
    }
    std::vector<std::string> getValues() const
    {
        return values_;
    }

    Operator getOperator() const
    {
        return operator_;
    }

 private:

    bool match(const std::string& lhs, const std::string& rhs) const;
    bool stringEquals(const std::string& lhs, const std::string& rhs) const;
    bool stringNotEquals(const std::string& lhs, const std::string& rhs) const;
    bool parseNumeric(const std::string& value, double& out) const;
    bool parseBool(const std::string& value, bool& out) const;
    bool boolEquals(const std::string& lhs, const std::string& rhs) const;
    bool numericCondition(const std::string& lhs, const std::string& rhs) const;

    Operator operator_;
    std::string key_;
    std::vector<std::string> values_;
};

} } // namespace
