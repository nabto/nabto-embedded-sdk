#pragma once

namespace nabto {
namespace iam {


enum class AttributeType {
    STRING,
    NUMBER
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

} }
