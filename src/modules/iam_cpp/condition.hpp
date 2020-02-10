#pragma once

namespace nabto {
namespace iam {

class Attributes;

class Condition {
 public:
    virtual ~Condition() {}
    virtual bool matches(const Attributes& attributes) const {
        return false;
    }
};

} } // namespace
