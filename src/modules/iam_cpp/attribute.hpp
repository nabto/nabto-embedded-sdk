#pragma once

namespace nabto {
namespace iam {


enum class AttributeType {
    STRING,
    NUMBER
};

class Attribute {
 public:
    Attribute(const Attribute& attribute)
        : type_(attribute.type_), string_(attribute.string_), number_(attribute.number_)
    {
    }

    Attribute(const std::string& str)
        : type_(AttributeType::STRING)
    {
        string_ = str;
    }
    Attribute(int64_t number)
        : type_(AttributeType::NUMBER)
    {
        number_ = number;
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
        return string_;
    }

    int64_t getNumber()
    {
        return number_;
    }

 private:
    AttributeType type_;
    std::string string_;
    int64_t number_;
};

} }
