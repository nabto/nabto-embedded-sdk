#include <boost/test/unit_test.hpp>

#include <modules/iam_cpp/iam_to_json.hpp>

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
    nabto::iam::
    BOOST_TEST(nabto::iam::IAMToJson::policyFromJson(testPolicy, ));
}

BOOST_AUTO_TEST_SUITE_END()
