#include <boost/test/unit_test.hpp>

#include <modules/iam_cpp/condition.hpp>
#include <modules/iam_cpp/attributes.hpp>

using namespace nabto::iam;

BOOST_TEST_DONT_PRINT_LOG_VALUE(Condition::Result)

BOOST_AUTO_TEST_SUITE(iam)

BOOST_AUTO_TEST_CASE(condition)
{
    Condition c(Condition::Operator::StringEquals, "foo", {"bar"});
    Attributes a;

    BOOST_TEST(c.matches(a) == Condition::Result::NO_MATCH);
    a.set("foo", "baz");
    BOOST_TEST(c.matches(a) == Condition::Result::NO_MATCH);
    a.set("foo", "bar");
    BOOST_TEST(c.matches(a) == Condition::Result::MATCH);
}

BOOST_AUTO_TEST_CASE(condition_variable)
{
    Condition c(Condition::Operator::StringEquals, "IAM:UserId", {"${Connection:UserId}"});
    Attributes a;

    BOOST_TEST(c.matches(a) == Condition::Result::NO_MATCH);
    a.set("IAM:UserId", "someuser");
    BOOST_TEST(c.matches(a) == Condition::Result::NO_MATCH);
    a.set("Connection:UserId", "somebar");
    BOOST_TEST(c.matches(a) == Condition::Result::NO_MATCH);
    a.set("Connection:UserId", "someuser");
    BOOST_TEST(c.matches(a) == Condition::Result::MATCH);
}

BOOST_AUTO_TEST_SUITE_END()
