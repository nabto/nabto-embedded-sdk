#include <boost/test/unit_test.hpp>

#include <modules/policies/nm_policies_json.h>

#include <cjson/cJSON.h>

namespace {

std::string s1 = R"(
{
  "Effect": "Allow",
  "Actions": ["foo"]
}
)";

std::string s2 = R"(
{
  "Effect": "Deny",
  "Actions": ["action1", "action2", "action3"],
  "Conditions": [
    {"StringEquals" : { "var1: ["val1", "val2", "val3"] } },
    {"NumericNotEquals" : {"var2": ["42", "43"] } }
  ]
}
)";

std::string i1 = R"(
{
  "Effect": "Invalid",
  "Actions": ["foo"]
}
)";

} // namespace

BOOST_AUTO_TEST_SUITE(policies_json)

BOOST_AUTO_TEST_CASE(parse_statenent1)
{
    struct nm_statement* s;
    cJSON* json = cJSON_Parse(s1.c_str());
    BOOST_TEST(json);
    s = nm_statenent_from_json(json);
    BOOST_TEST(c);
}

BOOST_AUTO_TEST_SUITE_END()
