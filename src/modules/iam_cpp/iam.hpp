#pragma once

namespace nabto {
namespace iam {

enum class AttributeType {
    STRING,
    NUMBER
};

class AttributeValue {
 public:
 private:
    AttributeType type_;
    union {
        std::string string_;
        int64_t number_;
    } value_;
};

class Attribute {
 public:
    Attribute(const std::string& string)
        : type_(AttributeType::STRING), value_.string_(string)
    {
    }
    Attribute(int64_t number)
        : type_(AttributeType::NUMBER), value_.number_(number)
    {
    }

    virtual ~Attribute() {}

    bool isString()
    {
        return type_ == AttributeType::STRING;
    }

    bool isNumber()
    {
        return type_ == AttributeType::NUMBER;
    }

    std::string getString()
    {
        return value_.string_;
    }

    std::string getNumber()
    {
        return value_.number_;
    }

 private:
    AttributeType type_;
    union {
        std::string string_;
        int64_t number_;
    } value_;
};

typedef std::map<std::string, Attribute> Attributes;

class User {
 public:
 private:
    std::string id_;
    std::set<std::string> roles_;
    Attributes attributes_;

};

class Session {
 public:
 private:
    std::set<std::string> roles_;
    Attributes attributes_;
};

class Role {
 public:
    static std::unique_ptr<
    std::vector<uint8_t> asCbor();
 private:
    std::set<Policy> policies_;
};

enum class Effect {
    ALLOW,
    DENY,
    NO_MATCH
};

class Condition {
 public:
};

class StringArgument {
 public:
    virtual ~StringArgument() {}
    virtual bool resolve(const std::map<std::string, Attribute>& attributes, std::string& result) = 0;
};

class ConstantStringArgument : public StringArgument {
 public:
    ConstantStringArgument(const std::string& constant)
        : constant_(constant)
    {
    }
    virtual bool resolve(const std::map<std::string, Attribute>& attributes, std::string& result)
    {
        result = constant_;
        return true;
    }
 private:
    std::string constant_;
};

class VariableStringArgument : public StringArgument {
 public:
    VariableStringArgument(const std::string& variableName)
        : variableName_(variableName)
    {
    }
    virtual bool resolve(const std::map<std::string, Attribute>& attributes, std::string& result)
    {
        auto it = attributes.find(variableName_);
        if (it == std::end(attributes)) {
            return false;
        } else if (!it->second.isString()) {
            return false;
        } else {
            result = it->second.getString();
            return true;
        }
    }
 private:
    std::string variableName_;
};

class NumberArgument {
 public:
    virtual ~NumberArgument() {}
    virtual bool resolve(const std::map<std::string, Attribute>& attributes, int64_t& result) = 0;
};

class ConstantNumberArgument : public NumberArgument {
 public:
    ConstantNumberArgument(int64_t number)
        : number_(number)
    {
    }
    virtual bool resolve(const std::map<std::string, Attribute>& attributes, int64_t& result)
    {
        result = number_;
        return true;
    }
 private:
    int64_t number_;

};

class VariableNumberArgument : public NumberArgument {
 public:
    VariableNumberArgument(const std::string& variable)
        : variable_(variable)
    {
    }
    virtual bool resolve(const std::map<std::string, Attribute>& attributes, int64_t& result)
    {
        auto it = attributes.find(variable_);
        if (it == std::end(attributes)) {
            return false;
        } else if (!it->second.isNumber()) {
            return false;
        } else {
            result = it->second.getNumber();
            return true;
        }
    }
 private:
    std::string variable_;
};


class Condition {
 public:
    virtual ~Condition() {}
    virtual bool matches(const std::map<std::string, Attribute>& attributes) = 0;
};

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

class Statement {
 private:
    /**
     * return true if actions and conditions is met.
     */
    bool matches();
 private:
    bool allow_;
    std::set<std::string> actions_;
    std::set<Condition> conditions_;
};

class Policy {
 public:
    Effect eval(const std::string& action, std::set<Attribute> attributes)
 private:
    std::vector<Statement> statements_;
};

class IAM {
 public:
 private:
    std::map<std::string, User> users_;
    std::map<std::string, Session> sessions_;
    std::map<std::string, Role> roles_;
    std::map<std::string, Policy> policies_;
};
