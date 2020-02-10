#pragma once

#include <modules/iam_cpp/policy.hpp>
#include <modules/iam_cpp/attributes.hpp>
#include <modules/iam_cpp/subject.hpp>

#include <memory>
#include <set>


namespace nabto {
namespace fingerprint_iam {

class Subject : public nabto::iam::Subject {
 public:
    Subject(const std::set<std::shared_ptr<nabto::iam::Policy> >& policies, const nabto::iam::Attributes& attributes)
        : policies_(policies), attributes_(attributes)
    {
    }
    virtual std::set<std::shared_ptr<nabto::iam::Policy> > getPolicies() const
    {
        return policies_;
    }
    virtual nabto::iam::Attributes getAttributes() const
    {
        return attributes_;
    }
 private:
    std::set<std::shared_ptr<nabto::iam::Policy> > policies_;
    nabto::iam::Attributes attributes_;
};

} } // namespace
