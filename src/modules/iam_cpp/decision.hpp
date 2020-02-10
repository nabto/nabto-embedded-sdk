#pragma once

#include <string>

namespace nabto {
namespace iam {

class Subject;
class Attributes;

class Decision {
 public:
    /**
     * Check access by checking the policies in the subject against
     * the action and attributes provided.
     */
    static bool checkAccess(const Subject& subject, const std::string& action, const Attributes& attributes);
};

} } // namespace
