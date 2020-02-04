#include <boost/test/unit_test.hpp>

#include <modules/iam_cpp/iam_to_json.hpp>


BOOST_AUTO_TEST_SUITE(iam)

// std::string testUsers = R"(
// {
//   "foo": {
//     "Roles": ["role1", "role2"],
//     "Attributes": {
//       "foo": "bar",
//       "baz": 42,
//       "isVeryImportant": false
//     }
//   },
//   "bar": {
//     "Roles": ["role1"]
//   }
// }
// )";

// BOOST_AUTO_TEST_CASE(load_user)
// {
//     std::vector<nabto::iam::User> users;
//     BOOST_TEST(nabto::iam::IAMToJson::usersFromJson(testUsers, users));
//     BOOST_TEST(users.size() == (size_t)2);
// }

BOOST_AUTO_TEST_SUITE_END()
