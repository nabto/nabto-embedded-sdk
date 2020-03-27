#include <boost/test/unit_test.hpp>

#include <modules/policies/nm_policy.h>
#include <modules/policies/nm_policies_from_json.h>

#include <nn/string_map.h>

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

} // namespace

BOOST_AUTO_TEST_SUITE(policies)

BOOST_AUTO_TEST_CASE(deny_ssh)
{
    cJSON* json = cJSON_Parse(denyPolicy.c_str());
    BOOST_REQUIRE(json);
    struct nm_policy* policy = nm_policy_from_json(json, NULL);
    BOOST_REQUIRE(policy);

    struct nn_string_map attributes;
    nn_string_map_init(&attributes);


    enum nm_effect effect;
    effect = nm_policy_eval(policy, "TcpTunnel:Connect", &attributes);
    BOOST_TEST(effect == NM_EFFECT_NO_MATCH);

    nn_string_map_insert(&attributes, "TcpTunnel:ServiceType", "ssh");
    effect = nm_policy_eval(policy, "TcpTunnel:Connect", &attributes);
    BOOST_TEST(effect == NM_EFFECT_DENY);

}

BOOST_AUTO_TEST_SUITE_END()
