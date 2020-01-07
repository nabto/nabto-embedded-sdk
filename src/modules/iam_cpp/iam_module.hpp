#pragma once

namespace nabto {
namespace iam {



class IAMModule {

 public:
    /**
     * Allow or deny an action,
     *
     * @param policies, the policies to use.
     * @param subjectAttributes, the subject attributes
     * @param action, the action which the subjects wants to make.
     * @param resourceAttributes, attributes describind the resource which is accessed.
     * @return true if the action is allowed.
     */
    bool decide(const std::set<std::string>& policies, const Attributes& subjectAttributes, const std::string& action, const Attributes& resourceAttributes);

 private:

};

} }
