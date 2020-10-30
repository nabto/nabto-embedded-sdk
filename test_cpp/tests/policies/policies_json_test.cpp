#include <boost/test/unit_test.hpp>

#include <modules/policies/nm_policies_from_json.h

namespace {

std::string p1 = R"(
{
  "Id": "Policy1",
  "Statements": [
    {
      "Effect": "Allow",
      "Actions": ["GetFoo", "PostBar"]
    },
    {
      "Effect": "Deny",
      "Actions": ["GetSuperSecret"]
    }
  ]
}
)";

} // namespace


BOOST_AUTO_TEST_SUITE(policy_json);

BOOST_AUTO_TEST_CASE()
{
    struct nm_iam_policy* p;
    cJSON* json = cJSON_Parse(c1.c_str());
    BOOST_TEST(json);
    c = nm_policy_from_json(json);
    BOOST_TEST(strcmp(c->id, "Policy1") == 0);
    BOOST_TEST(nn_llist_size(&c->statements) == 2);
    nm_policy_free(c);
}

BOOST_AUTO_TEST_SUITE_END()
