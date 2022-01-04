#include <boost/test/unit_test.hpp>

#include <modules/iam/policies/nm_statement.h>
#include <modules/iam/policies/nm_condition.h>
#include <modules/iam/policies/nm_policies_from_json.h>
#include <nn/string_map.h>

#include <platform/np_allocator.h>

#include <cjson/cJSON.h>


std::string sAllow = R"(
{
  "Effect": "Allow",
  "Actions": ["action1"],
  "Conditions": [
    {"StringEquals": { "var1": ["val1"] } },
    {"StringEquals": { "var2": ["val2"] } }
  ]
}
)";

std::string sDeny = R"(
{
  "Effect": "Deny",
  "Actions": ["action1"],
  "Conditions": [
    {"StringEquals": { "var1": ["val1"] } },
    {"StringEquals": { "var2": ["val2"] } }
  ]
}
)";


BOOST_AUTO_TEST_SUITE(statement_eval)

BOOST_AUTO_TEST_CASE(match_all_allow_raw)
{
    struct nm_iam_statement* s = nm_statement_new(NM_IAM_EFFECT_ALLOW);
    BOOST_REQUIRE(s);
    nm_statement_add_action(s, "action1");
    struct nm_iam_condition* c = nm_condition_new_with_key(NM_IAM_CONDITION_OPERATOR_STRING_EQUALS, "var1");
    BOOST_REQUIRE(c);
    BOOST_REQUIRE(nm_condition_add_value(c, "val1"));
    BOOST_REQUIRE(nm_statement_add_condition(s, c));
    c = nm_condition_new_with_key(NM_IAM_CONDITION_OPERATOR_STRING_EQUALS, "var2");
    BOOST_REQUIRE(c);
    BOOST_REQUIRE(nm_condition_add_value(c, "val2"));
    BOOST_REQUIRE(nm_statement_add_condition(s, c));


    struct nn_string_map attributes;
    nn_string_map_init(&attributes, np_allocator_get());

    BOOST_TEST(nm_statement_eval(s, "action1", &attributes) == NM_IAM_EFFECT_NO_MATCH);

    nn_string_map_insert(&attributes, "var1", "val1");

    BOOST_TEST(nm_statement_eval(s, "action1", &attributes) == NM_IAM_EFFECT_NO_MATCH);

    nn_string_map_insert(&attributes, "var2", "val2");

    BOOST_TEST(nm_statement_eval(s, "action0", &attributes) == NM_IAM_EFFECT_NO_MATCH);

    BOOST_TEST(nm_statement_eval(s, "action1", &attributes) == NM_IAM_EFFECT_ALLOW);

    nn_string_map_deinit(&attributes);
    nm_statement_free(s);
}

BOOST_AUTO_TEST_CASE(match_all_allow_json)
{
    struct nm_iam_statement* s;
    cJSON* json = cJSON_Parse(sAllow.c_str());
    BOOST_REQUIRE(json);
    s = nm_statement_from_json(json, NULL);
    BOOST_REQUIRE(s);
    struct nn_string_map attributes;
    nn_string_map_init(&attributes, np_allocator_get());

    BOOST_TEST(nm_statement_eval(s, "action1", &attributes) == NM_IAM_EFFECT_NO_MATCH);

    nn_string_map_insert(&attributes, "var1", "val1");

    BOOST_TEST(nm_statement_eval(s, "action1", &attributes) == NM_IAM_EFFECT_NO_MATCH);

    nn_string_map_insert(&attributes, "var2", "val2");

    BOOST_TEST(nm_statement_eval(s, "action0", &attributes) == NM_IAM_EFFECT_NO_MATCH);

    BOOST_TEST(nm_statement_eval(s, "action1", &attributes) == NM_IAM_EFFECT_ALLOW);

    nn_string_map_deinit(&attributes);
    nm_statement_free(s);
    cJSON_Delete(json);
}

BOOST_AUTO_TEST_CASE(match_all_deny)
{
    struct nm_iam_statement* s;
    cJSON* json = cJSON_Parse(sDeny.c_str());
    BOOST_REQUIRE(json);
    s = nm_statement_from_json(json, NULL);
    BOOST_REQUIRE(s);
    struct nn_string_map attributes;
    nn_string_map_init(&attributes, np_allocator_get());

    BOOST_TEST(nm_statement_eval(s, "action1", &attributes) == NM_IAM_EFFECT_NO_MATCH);

    nn_string_map_insert(&attributes, "var1", "val1");

    BOOST_TEST(nm_statement_eval(s, "action1", &attributes) == NM_IAM_EFFECT_NO_MATCH);

    nn_string_map_insert(&attributes, "var2", "val2");

    BOOST_TEST(nm_statement_eval(s, "action0", &attributes) == NM_IAM_EFFECT_NO_MATCH);

    BOOST_TEST(nm_statement_eval(s, "action1", &attributes) == NM_IAM_EFFECT_DENY);

    nn_string_map_deinit(&attributes);
    nm_statement_free(s);
    cJSON_Delete(json);
}

BOOST_AUTO_TEST_SUITE_END()
