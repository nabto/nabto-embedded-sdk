#pragma once

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
 private:
    std::string id_;
    std::set<std::string> roles_;
    Attributes attributes_;
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
    virtual ~Condition() {}
    virtual bool matches(const Attributes& attributes) = 0;
};

class Context {
 public:
    Attributes& attributes();
};

class Statement {
 private:
    /**
     * return true if actions and conditions is met.
     */
    bool matches();
    Effect eval(const std::string& action, const Attributes& attributes);
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
