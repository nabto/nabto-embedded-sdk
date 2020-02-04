#include <boost/test/unit_test.hpp>

#include <modules/iam_cpp/iam_to_json.hpp>

BOOST_AUTO_TEST_SUITE(iam)

// std::string testRoles = R"(
// {
//   "admin" : {
//     "Policies": [ "DeleteEverything", "BOFH", "AddUsers" ]
//   },
//   "guest": {
//     "Policies": [ "ReadData" ]
//   }
// }
// )";

// BOOST_AUTO_TEST_CASE(load_roles)
// {
//     std::vector<nabto::iam::Role> roles;
//     BOOST_TEST(nabto::iam::IAMToJson::rolesFromJson(testRoles, roles));
//     BOOST_TEST(roles.size() == (size_t)2);
// }

BOOST_AUTO_TEST_SUITE_END()
