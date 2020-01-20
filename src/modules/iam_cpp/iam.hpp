#pragma once

#include "attribute.hpp"
#include <set>

namespace nabto {
namespace iam {

typedef std::map<std::string, Attribute> Attributes;

/**
 * A subject is e.g. a User.
 */
class Subject {
 public:
    virtual std::set<std::string> policies() = 0;
    virtual Attributes& attributes() = 0;
};

class User : public Subject {
 public:

    User(const std::string& id) : id_(id) {}

    std::set<std::string> policies() {
        return std::set<std::string>();
    }
    Attributes& attributes() {
        return attributes_;
    }

    void addRole(const std::string& role) {
        roles_.insert(role);
    }

    void removeRole(const std::string& role) {
        roles_.erase(role);
    }

    void addAttribute(const std::string& key, const Attribute& value) {
        attributes_.insert(std::make_pair(key,value));
    }

    void removeAttribute(const std::string& key) {
        attributes_.erase(key);
    }
 private:
    std::string id_;
    std::set<std::string> roles_;
    Attributes attributes_;
};

class Session : public Subject {

};


/**
 * An action describes an action. The action is a string like
 * HeatPump:Read HeatPump:WriteTarget.
 */
class Action {
 public:
    std::string action();
};

/**
 * A resource describes attributes for a resource. A resource could be
 * a HeatPump write target endpoint. A resource attribute could be
 * current target temperature.
 */
class Resource {
 public:
    Attributes& attributes();
};

class Role {
 public:
    Role(const std::string& name) : name_(name) {}

    void addPolicy(const std::string& policy) {
        policies_.insert(policy);
    }
 private:
    std::string name_;
    std::set<std::string> policies_;
};

enum class Effect {
    ALLOW,
    DENY,
    NO_MATCH
};

class Condition {
 public:
    virtual ~Condition() {}
    virtual bool matches(const Attributes& attributes) = 0;
};

class Context {
 public:
    Attributes& attributes();
};

class Statement {
 public:
    /**
     * return true if actions and conditions is met.
     */
    bool matches();
    Effect eval(const std::string& action, const Attributes& attributes);

    Statement(Effect effect, std::set<std::string> actions)
        : effect_(effect), actions_(actions)
    {
    }

 private:
    bool matchActions(const std::string& action);

    bool matchCondition(const Condition& condition, const Attributes& attributes);
    bool matchConditions(const Attributes& attributes);

    Effect effect_;
    /**
     * List of actions this statement matches
     */
    std::set<std::string> actions_;
    std::vector<Condition> conditions_;
};

class Policy {
 public:
    Effect eval(const std::string& action, const Attributes& attributes);
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

} } // namespace
