#include <boost/test/unit_test.hpp>

#include <modules/policies/nm_condition.h>

BOOST_AUTO_TEST_SUITE(policies)

BOOST_AUTO_TEST_CASE(parse_bool)
{
    const char* f = "false";
    const char* t = "true";
    const char* invalid1 = "";
    const char* invalid2 = "foo";

    bool out;
    BOOST_TEST(nm_condition_parse_bool(f,&out));
    BOOST_TEST(out == false);

    BOOST_TEST(nm_condition_parse_bool(t,&out));
    BOOST_TEST(out == true);

    BOOST_TEST(!nm_condition_parse_bool(invalid1, &out));
    BOOST_TEST(!nm_condition_parse_bool(invalid2, &out));
}

BOOST_AUTO_TEST_SUITE_END()
