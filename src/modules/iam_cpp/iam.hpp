#pragma once

#include "attribute.hpp"
#include "iam_persisting.hpp"
#include <set>
#include <map>
#include <vector>

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

    User() {}

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

    std::set<std::string> getRoles() const {
        return roles_;
    }

    Attributes getAttributes() const {
        return attributes_;
    }

    std::string getName() const {
        return id_;
    }
 private:
    std::string id_;
    std::set<std::string> roles_;
    Attributes attributes_;
};

class Session : public Subject {
 public:
    virtual std::set<std::string> policies()
    {
        return std::set<std::string>();
    };
    virtual Attributes& attributes()
    {
        return attributes_;
    };
 private:
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
    Role() {}
    Role(const std::string& name) : name_(name) {}
    Role(const std::string& name, const std::set<std::string>& policies) : name_(name), policies_(policies) {}

    void addPolicy(const std::string& policy)
    {
        policies_.insert(policy);
    }
    std::string getName() const
    {
        return name_;
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
    virtual bool matches(const Attributes& attributes)
    {
        return false;
    }
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

    Statement(Effect effect, std::set<std::string> actions, std::vector<Condition> conditions)
        : effect_(effect), actions_(actions), conditions_(conditions)
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

    Policy() {}

    Policy(const std::string& name, std::vector<Statement> statements)
        : name_(name), statements_(statements)
    {
    }

    Effect eval(const std::string& action, const Attributes& attributes);

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

class IAM {
 public:
    IAM() {}

    void addUser(const User& user)
    {
        users_[user.getName()] = user;
        if (persisting_) {
            persisting_->upsertUser(user);
        }
    }

    void removeUser(const std::string& userId)
    {
        users_.erase(userId);
        if (persisting_) {
            persisting_->deleteUser(userId);
        }
    }

    void updateUser(const User& user)
    {
        users_[user.getName()] = user;
        if (persisting_) {
            persisting_->upsertUser(user);
        }
    }

    void addRole(const Role& role)
    {
        roles_[role.getName()] = role;
        if (persisting_) {
            persisting_->upsertRole(role);
        }
    }

    void removeRole(const std::string& roleName)
    {
        roles_.erase(roleName);
        if (persisting_) {
            persisting_->deleteRole(roleName);
        }
    }

    void updateRole(const Role& role)
    {
        roles_[role.getName()] = role;
        if (persisting_) {
            persisting_->upsertRole(role);
        }
    }

    void addPolicy(const Policy& policy)
    {
        policies_[policy.getName()] = policy;
        if (persisting_) {
            persisting_->upsertPolicy(policy);
        }
    }

    void removePolicy(const std::string& policyName)
    {
        policies_.erase(policyName);
        if (persisting_) {
            persisting_->deletePolicy(policyName);
        }
    }

    void updatePolicy(const Policy& policy)
    {
        policies_[policy.getName()] = policy;
        if (persisting_) {
            persisting_->upsertPolicy(policy);
        }
    }

    void setPersistingAdapter(IAMPersisting* persisting)
    {
        persisting_ = persisting;
    }

    bool checkIamAccess(const Subject& subject, const std::string& action, const Attributes& attributes);

 private:
    std::map<std::string, User> users_;
    std::map<std::string, Session> sessions_;
    std::map<std::string, Role> roles_;
    std::map<std::string, Policy> policies_;

    IAMPersisting* persisting_ = NULL;
};

} } // namespace
