#pragma once

#include <boost/system/error_code.hpp>
#include <sstream>

namespace lib {
    namespace errc = boost::system::errc;
    using boost::system::error_code;
    using boost::system::error_category;
    using boost::system::error_condition;
//    using boost::system::system_error;
}

#define NABTO_ERROR_CODE_ENUM_NAMESPACE_START namespace boost { namespace system {
#define NABTO_ERROR_CODE_ENUM_NAMESPACE_END }}


namespace nabto {

class TestError : public lib::error_category
{
 public:
    enum ErrorCodes {
        ok,
        stopped,
        canceled,
        timeout,
        aborted,
        closed,
        end_of_file,
        never_here,
        operation_in_progress,
        invalid_argument,
        invalid_state,
        no_data,
        not_implemented,
        bad_response,
        not_found,
        forbidden,
        failed
    };
    const char* name() const noexcept { return "Test errors"; }
    std::string message(int e) const {
        switch(e) {
            case ok: return "Ok";
            case stopped: return "Stopped";
            case canceled: return "Operation canceled";
            case timeout: return "Timeout";
            case aborted: return "Aborted";
            case closed: return "Closed";
            case end_of_file: return "End of file";
            case never_here: return "We should never end here";
            case operation_in_progress: return "Operation in progress";
            case invalid_argument: return "Invalid argument";
            case invalid_state: return "Invalid state";
            case no_data: return "No data";
            case not_implemented: return "Not implemented";
            case bad_response: return "Bad response";
            case not_found: return "Not found";
            case forbidden: return "Forbidden";
            case failed: return "Operation failed";
            default: {
                std::stringstream ss;
                ss << "default error message " << e;
                return ss.str();
            }
        }
    }
};

class TestErrorCategoryContainer {
 public:
    static TestError& category() {
        static TestError category;
        return category;
    }
};

static inline lib::error_code make_error_code(TestError::ErrorCodes e) {
    return lib::error_code(static_cast<int>(e), TestErrorCategoryContainer::category());
}

} // namespace

NABTO_ERROR_CODE_ENUM_NAMESPACE_START

template<> struct is_error_code_enum<nabto::TestError::ErrorCodes>
{
    BOOST_STATIC_CONSTANT(bool, value = true);
};

NABTO_ERROR_CODE_ENUM_NAMESPACE_END
