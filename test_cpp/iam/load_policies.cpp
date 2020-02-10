#include <boost/test/unit_test.hpp>

#include <modules/iam_cpp/iam_to_json.hpp>
#include <modules/iam_cpp/policy.hpp>

BOOST_AUTO_TEST_SUITE(iam)

std::string testPolicy = R"(
{
  "Version": 1,
  "Name": "ReadData",
  "Statement": [
    {
      "Effect": "Allow",
      "Actions": ["readfoo", "readbar"]
    }
  ]
}
)";

BOOST_AUTO_TEST_CASE(load_policies)
{
    std::unique_ptr<nabto::iam::Policy> policy = nabto::iam::IAMToJson::policyFromJson(testPolicy);
    BOOST_TEST((policy != nullptr));
}

BOOST_AUTO_TEST_SUITE_END()
