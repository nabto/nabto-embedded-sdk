#include <boost/test/unit_test.hpp>

#include <modules/iam/policies/nm_policy.h>
#include <modules/iam/policies/nm_policies_from_json.h>

#include <nn/string_map.h>
#include <platform/np_allocator.h>

#include <cjson/cJSON.h>


namespace {
std::string denyPolicy = R"(
{
  "Id": "DenySSH",
  "Statements": [
    {
      "Effect": "Deny",
      "Actions": ["TcpTunnel:Connect"],
      "Conditions": [
        {"StringEquals" : {"TcpTunnel:ServiceType": [ "ssh" ] } }
      ]
    }
  ]
}
)";

std::string allowDenyPolicy = R"(
{
  "Id": "AllowDeny",
  "Statements": [
    {
      "Effect": "Allow",
      "Actions": ["TcpTunnel:Connect"]
    },
    {
      "Effect": "Deny",
      "Actions": ["TcpTunnel:Connect"]
    }
  ]
}
)";

} // namespace

BOOST_AUTO_TEST_SUITE(policy)

BOOST_AUTO_TEST_CASE(deny_ssh)
{
    cJSON* json = cJSON_Parse(denyPolicy.c_str());
    BOOST_REQUIRE(json);
    struct nm_iam_policy* policy = nm_policy_from_json(json, NULL);
    BOOST_REQUIRE(policy);

    struct nn_string_map attributes;
    nn_string_map_init(&attributes, np_allocator_get());

    BOOST_TEST(nm_policy_eval_simple(policy, "TcpTunnel:Connect", &attributes) == NM_IAM_EFFECT_NO_MATCH);

    nn_string_map_insert(&attributes, "TcpTunnel:ServiceType", "ssh");
    BOOST_TEST(nm_policy_eval_simple(policy, "TcpTunnel:Connect", &attributes) == NM_IAM_EFFECT_DENY);

    nn_string_map_deinit(&attributes);
    nm_policy_free(policy);
    cJSON_Delete(json);
}

BOOST_AUTO_TEST_CASE(deny_trumps_allow)
{
    cJSON* json = cJSON_Parse(allowDenyPolicy.c_str());
    BOOST_REQUIRE(json);
    struct nm_iam_policy* policy = nm_policy_from_json(json, NULL);
    BOOST_REQUIRE(policy);

    BOOST_TEST(nm_policy_eval_simple(policy, "TcpTunnel:Connect", NULL) == NM_IAM_EFFECT_DENY);

    nm_policy_free(policy);
    cJSON_Delete(json);

}

BOOST_AUTO_TEST_SUITE_END()
