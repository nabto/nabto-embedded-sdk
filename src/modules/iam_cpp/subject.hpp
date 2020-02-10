#pragma once

#include "attributes.hpp"

#include <set>
#include <memory>


namespace nabto {
namespace iam {

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

} } // namespace
