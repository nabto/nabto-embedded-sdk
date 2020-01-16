#pragme once

namespace nabto {
namespace iam {


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

} }
