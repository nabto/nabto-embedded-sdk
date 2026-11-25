#define BOOST_TEST_MODULE unit_test
#include <boost/test/unit_test.hpp>

#include <platform/np_ref.h>

#include <cstdlib>
#include <iostream>
#include <string>

extern "C" {
// Provided by the address sanitizer runtime, if it is linked in.
void __sanitizer_print_stack_trace() __attribute__((weak));
}

namespace {

/**
 * Print each violation, with a stack trace if the test runs with a
 * sanitizer. Enabled with NABTO_TEST_TRACE_LIFETIME_VIOLATIONS=1.
 */
void traceViolation(const char* what)
{
    std::cerr << "Lifetime contract violation: " << what << std::endl;
    if (__sanitizer_print_stack_trace) {
        __sanitizer_print_stack_trace();
    }
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
