#include <boost/test/unit_test.hpp>

#include <modules/policies/nm_policies_from_json.h>

#include <modules/policies/nm_condition.h>
#include <modules/policies/nm_statement.h>
#include <nn/string_set.h>

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
    {"StringEquals": { "var1": ["val1", "val2", "val3"] } },
    {"NumericNotEquals": { "var2": ["42", "43"] } }
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

BOOST_AUTO_TEST_SUITE(statement_json)

BOOST_AUTO_TEST_CASE(parse_statement1)
{
    struct nm_statement* s;
    cJSON* json = cJSON_Parse(s1.c_str());
    BOOST_TEST(json);
    s = nm_statement_from_json(json, NULL);
    BOOST_TEST(s);
    BOOST_TEST(s->effect == NM_EFFECT_ALLOW);
    BOOST_TEST(nn_string_set_contains(&s->actions, "foo"));
    nm_statement_free(s);
    cJSON_Delete(json);
}

BOOST_AUTO_TEST_CASE(parse_statement2)
{
    struct nm_statement* s;
    cJSON* json = cJSON_Parse(s2.c_str());
    BOOST_TEST(json);
    s = nm_statement_from_json(json, NULL);
    BOOST_TEST(s);
    BOOST_TEST(s->effect == NM_EFFECT_DENY);
    BOOST_TEST(nn_string_set_contains(&s->actions, "action2"));
    BOOST_TEST(nn_vector_size(&s->conditions) == (size_t)2);
    nm_statement_free(s);
    cJSON_Delete(json);
}

BOOST_AUTO_TEST_CASE(parse_statement_fail1)
{
    struct nm_statement* s;
    cJSON* json = cJSON_Parse(i1.c_str());
    BOOST_TEST(json);
    s = nm_statement_from_json(json, NULL);
    BOOST_TEST(!s);
    cJSON_Delete(json);
}

BOOST_AUTO_TEST_SUITE_END()
