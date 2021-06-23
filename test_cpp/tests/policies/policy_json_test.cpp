#include <boost/test/unit_test.hpp>

#include <modules/iam/policies/nm_policies_from_json.h>

#include <nn/llist.h>
#include <modules/iam/policies/nm_policy.h>

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


BOOST_AUTO_TEST_SUITE(policy_json)

BOOST_AUTO_TEST_CASE(parse1)
{
    struct nm_iam_policy* p;
    cJSON* json = cJSON_Parse(p1.c_str());
    BOOST_TEST(json);
    p = nm_policy_from_json(json, NULL);
    BOOST_TEST(strcmp(p->id, "Policy1") == 0);
    BOOST_TEST(nn_llist_size(&p->statements) == (size_t)2);
    nm_policy_free(p);
    cJSON_Delete(json);
}

BOOST_AUTO_TEST_SUITE_END()
