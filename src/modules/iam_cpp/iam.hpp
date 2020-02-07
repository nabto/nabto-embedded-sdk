#pragma once

#include "attribute.hpp"
#include "iam_persisting.hpp"
#include <set>
#include <map>
#include <vector>

#include <memory>

namespace nabto {
namespace iam {

typedef std::map<std::string, Attribute> AttributeMap;

class Attributes {
 public:
    Attributes() {}
    Attributes(AttributeMap map) : attributes_(map) {}
    std::unique_ptr<Attribute> get(const std::string& key) const;
    AttributeMap getMap() const;
    void merge(const Attributes& attributes);
 private:
    AttributeMap attributes_;
};

class Policy;

/**
 * A subject is e.g. a User.
 */
class Subject {
 public:
    virtual ~Subject() {}
    virtual std::set<std::shared_ptr<Policy> > getPolicies() const = 0;
    virtual Attributes getAttributes() const = 0;
};

enum class Effect {
    ALLOW,
    DENY,
    NO_MATCH
};

class Condition {
 public:
    virtual ~Condition() {}
    virtual bool matches(const Attributes& attributes) const {
        return false;
    }
};

class Statement {
 public:
    Statement(Effect effect, std::set<std::string> actions, std::vector<Condition> conditions)
        : effect_(effect), actions_(actions), conditions_(conditions)
    {
    }

    Effect eval(const std::string& action, const Attributes& attributes) const;

 private:
    bool matchActions(const std::string& action) const;

    bool matchConditions(const Attributes& attributes) const;

    Effect effect_;
    /**
     * List of actions this statement matches
     */
    std::set<std::string> actions_;
    std::vector<Condition> conditions_;
};

class Policy {
 public:

    Policy() {}

    Policy(const std::string& name, std::vector<Statement> statements)
        : name_(name), statements_(statements)
    {
    }

    Effect eval(const std::string& action, const Attributes& attributes) const;

    void addStatement(Statement statement)
    {
        statements_.push_back(statement);
    }

    void setVersion(int version)
    {
        version_ = version;
    }

    void setName(const std::string& name)
    {
        name_ = name;
    }

    std::string getName() const
    {
        return name_;
    }
 private:
    int version_;
    std::string name_;
    std::vector<Statement> statements_;
};

class IamPdp {
 public:
    static bool checkAccess(const Subject& subject, const std::string& action, const Attributes& attributes);
};

} } // namespace
