#include <boost/test/unit_test.hpp>

#include <modules/iam/nm_iam_to_json.h>
#include <modules/iam/nm_iam_from_json.h>
#include <modules/iam/nm_iam_user.h>

BOOST_AUTO_TEST_SUITE(iam)

BOOST_AUTO_TEST_CASE(user_to_json)
{
    struct nm_iam_user user;
    nm_iam_user_init(&user);

    user.id = strdup("1");
    np_string_set_add(&user.roles, "role1");
    user.fingerprint = strdup("fp");
    user.serverConnectToken = strdup("sct");
    np_string_map_insert(&user.attributes, "key", "value");

    cJSON* json = nm_iam_user_to_json(&user);

    struct nm_iam_user* decoded = nm_iam_user_from_json(json);

    BOOST_TEST(strcmp(user.id, decoded->id) == 0);
    BOOST_TEST(strcmp(user.fingerprint, decoded->fingerprint) == 0);
    BOOST_TEST(strcmp(user.serverConnectToken, decoded->serverConnectToken) == 0);
    BOOST_TEST(np_string_set_size(&user.roles) == np_string_set_size(&decoded->roles));
    BOOST_TEST(np_string_map_size(&user.attributes) == np_string_map_size(&decoded->attributes));

}

BOOST_AUTO_TEST_SUITE_END()
