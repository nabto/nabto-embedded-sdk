#define BOOST_TEST_MODULE unit_test
#include <boost/test/unit_test.hpp>

#include <platform/np_ref.h>

#include <cstdlib>
#include <iostream>
#include <string>

// Print stack traces of violations when the test is built with the address
// sanitizer.
#if defined(__SANITIZE_ADDRESS__)
#define NABTO_TEST_HAS_ASAN
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define NABTO_TEST_HAS_ASAN
#endif
#endif

#if defined(NABTO_TEST_HAS_ASAN)
#include <sanitizer/common_interface_defs.h>
#endif

namespace {

/**
 * Print each violation, with a stack trace if the test is built with the
 * address sanitizer. Enabled with NABTO_TEST_TRACE_LIFETIME_VIOLATIONS=1.
 */
void traceViolation(const char* what)
{
    std::cerr << "Lifetime contract violation: " << what << std::endl;
#if defined(NABTO_TEST_HAS_ASAN)
    __sanitizer_print_stack_trace();
#endif
}

/**
 * Report the test cases which break a lifetime contract, see
 * np_lifetime_violation.
 */
class LifetimeViolationObserver : public boost::unit_test::test_observer {
 public:
    void test_unit_start(boost::unit_test::test_unit const& /*tu*/) override
    {
        before_ = np_lifetime_violation_count();
    }

    void test_unit_finish(boost::unit_test::test_unit const& tu, unsigned long /*elapsed*/) override
    {
        if (tu.p_type != boost::unit_test::TUT_CASE) {
            return;
        }
        size_t violations = np_lifetime_violation_count() - before_;
        if (violations > 0) {
            std::cerr << "Lifetime contract violations: " << violations << " in " << tu.full_name() << std::endl;
        }
    }

 private:
    size_t before_ = 0;
};

struct LifetimeViolationFixture {
    LifetimeViolationFixture()
    {
        const char* trace = std::getenv("NABTO_TEST_TRACE_LIFETIME_VIOLATIONS");
        if (trace != nullptr && std::string(trace) == "1") {
            np_lifetime_violation_hook = &traceViolation;
        }
        boost::unit_test::framework::register_observer(observer_);
    }
    ~LifetimeViolationFixture()
    {
        boost::unit_test::framework::deregister_observer(observer_);
    }
    LifetimeViolationObserver observer_;
};

} // namespace

BOOST_TEST_GLOBAL_FIXTURE(LifetimeViolationFixture);
