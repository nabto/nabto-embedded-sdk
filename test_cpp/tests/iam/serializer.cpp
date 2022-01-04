#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <modules/iam/nm_iam_user.h>
#include <modules/iam/nm_iam_serializer.h>
#include <nn/llist.h>
#include <nn/string_set.h>
#include <nlohmann/json.hpp>

#include <platform/np_allocator.h>

namespace {

std::string s1 = R"(
{
  "OpenPairingPassword":"password",
  "OpenPairingSct":"token",
  "Users": [
    {
      "DisplayName":"Display Name",
      "Fingerprint":"fingerprint",
      "Role":"role1",
      "ServerConnectToken":"token2",
      "Password":"password2",
      "Username":"username",
      "Fcm": {
        "Token":"fcm_token",
        "ProjectId":"fcm_project"
      },
      "NotificationCategories": ["cat1","cat2"]
    }
  ],
  "Version":1
}
)";

std::string c1 = R"(
{
  "Config": {
    "UnpairedRole":"TestRole"
  },
  "Policies": [
    {
      "Id":"TestPolicy",
      "Statements": [
        {
          "Actions":[
            "Test:foo",
            "Test:bar"
          ],
          "Effect":"Allow"
        }
      ]
    }
  ],
  "Roles":[
    {
      "Id":"TestRole",
      "Policies":[
        "TestPolicy"
      ]
    }
  ],
  "Version":1
}
)";

} // namespace

BOOST_AUTO_TEST_SUITE(iam)

BOOST_AUTO_TEST_CASE(serialize_config_to_json, *boost::unit_test::timeout(180))
{
    struct nm_iam_configuration* conf = nm_iam_configuration_new();
    {
        struct nm_iam_policy* p = nm_iam_configuration_policy_new("TestPolicy");
        struct nm_iam_statement* stmt = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(stmt, "Test:foo");
        nm_iam_configuration_statement_add_action(stmt, "Test:bar");
        nm_iam_configuration_add_policy(conf, p);
    }

    {
        struct nm_iam_role* testRole = nm_iam_configuration_role_new("TestRole");
        nm_iam_configuration_role_add_policy(testRole, "TestPolicy");
        nm_iam_configuration_add_role(conf, testRole);
    }

    {
        nm_iam_configuration_set_unpaired_role(conf, "TestRole");
    }

    char* iamConf;
    BOOST_TEST(nm_iam_serializer_configuration_dump_json(conf, &iamConf));

    nlohmann::json j = nlohmann::json::parse(iamConf);
    BOOST_TEST(j["Config"].is_object());
    BOOST_TEST(j["Config"]["UnpairedRole"].is_string());
    BOOST_TEST(j["Config"]["UnpairedRole"].get<std::string>().compare("TestRole") == 0);

    BOOST_TEST(j["Policies"].is_array());
    BOOST_TEST(j["Policies"].size() == (size_t)1);
    BOOST_TEST(j["Policies"][0]["Id"].is_string());
    BOOST_TEST(j["Policies"][0]["Id"].get<std::string>().compare("TestPolicy") == 0);
    BOOST_TEST(j["Policies"][0]["Statements"].is_array());
    BOOST_TEST(j["Policies"][0]["Statements"].size() == (size_t)1);
    BOOST_TEST(j["Policies"][0]["Statements"][0]["Actions"].is_array());
    BOOST_TEST(j["Policies"][0]["Statements"][0]["Actions"].size() == (size_t)2);
    BOOST_TEST(j["Policies"][0]["Statements"][0]["Actions"][0].is_string());
    BOOST_TEST(j["Policies"][0]["Statements"][0]["Actions"][0].get<std::string>().compare("Test:foo") == 0);
    BOOST_TEST(j["Policies"][0]["Statements"][0]["Actions"][1].is_string());
    BOOST_TEST(j["Policies"][0]["Statements"][0]["Actions"][1].get<std::string>().compare("Test:bar") == 0);
    BOOST_TEST(j["Policies"][0]["Statements"][0]["Effect"].is_string());
    BOOST_TEST(j["Policies"][0]["Statements"][0]["Effect"].get<std::string>().compare("Allow") == 0);

    BOOST_TEST(j["Roles"].is_array());
    BOOST_TEST(j["Roles"].size() == (size_t)1);
    BOOST_TEST(j["Roles"][0]["Id"].is_string());
    BOOST_TEST(j["Roles"][0]["Id"].get<std::string>().compare("TestRole") == 0);
    BOOST_TEST(j["Roles"][0]["Policies"].is_array());
    BOOST_TEST(j["Roles"][0]["Policies"].size() == (size_t)1);
    BOOST_TEST(j["Roles"][0]["Policies"][0].is_string());
    BOOST_TEST(j["Roles"][0]["Policies"][0].get<std::string>().compare("TestPolicy") == 0);

    BOOST_TEST(j["Version"].is_number());
    BOOST_TEST(j["Version"].get<int>() == 1);

    nm_iam_configuration_free(conf);
    nm_iam_serializer_string_free(iamConf);
}

BOOST_AUTO_TEST_CASE(serialize_state_to_json, *boost::unit_test::timeout(180))
{
    struct nm_iam_state* state = nm_iam_state_new();
    {
        BOOST_TEST(nm_iam_state_set_password_open_password(state, "password") == true);
        BOOST_TEST(nm_iam_state_set_password_open_sct(state, "token") == true);
    }
    {
        struct nn_string_set cats;
        nn_string_set_init(&cats, np_allocator_get());
        nn_string_set_insert(&cats, "cat1");
        nn_string_set_insert(&cats, "cat2");
        struct nm_iam_user* u = nm_iam_user_new("username");
        BOOST_TEST(nm_iam_user_set_fingerprint(u, "fingerprint") == true);
        BOOST_TEST(nm_iam_user_set_sct(u, "token2") == true);
        BOOST_TEST(nm_iam_user_set_display_name(u, "Display Name") == true);
        BOOST_TEST(nm_iam_user_set_role(u, "role1") == true);
        BOOST_TEST(nm_iam_user_set_password(u, "password2") == true);
        BOOST_TEST(nm_iam_user_set_fcm_token(u, "fcm_token") == true);
        BOOST_TEST(nm_iam_user_set_fcm_project_id(u, "fcm_project") == true);
        BOOST_TEST(nm_iam_user_set_notification_categories(u, &cats) == true);
        BOOST_TEST(nm_iam_state_add_user(state, u) == true);
        nn_string_set_deinit(&cats);
    }
    char* jStr;
    BOOST_TEST(nm_iam_serializer_state_dump_json(state, &jStr) == true);

    nlohmann::json j = nlohmann::json::parse(jStr);

    BOOST_TEST(j["OpenPairingPassword"].is_string());
    BOOST_TEST(j["OpenPairingPassword"].get<std::string>().compare("password") == 0);

    BOOST_TEST(j["OpenPairingSct"].is_string());
    BOOST_TEST(j["OpenPairingSct"].get<std::string>().compare("token") == 0);

    BOOST_TEST(j["Users"].is_array());
    BOOST_TEST(j["Users"].size() == (size_t)1);
    BOOST_TEST(j["Users"][0]["Username"].is_string());
    BOOST_TEST(j["Users"][0]["Username"].get<std::string>().compare("username") == 0);
    BOOST_TEST(j["Users"][0]["Fingerprint"].is_string());
    BOOST_TEST(j["Users"][0]["Fingerprint"].get<std::string>().compare("fingerprint") == 0);
    BOOST_TEST(j["Users"][0]["ServerConnectToken"].is_string());
    BOOST_TEST(j["Users"][0]["ServerConnectToken"].get<std::string>().compare("token2") == 0);
    BOOST_TEST(j["Users"][0]["DisplayName"].is_string());
    BOOST_TEST(j["Users"][0]["DisplayName"].get<std::string>().compare("Display Name") == 0);
    BOOST_TEST(j["Users"][0]["Role"].is_string());
    BOOST_TEST(j["Users"][0]["Role"].get<std::string>().compare("role1") == 0);
    BOOST_TEST(j["Users"][0]["Password"].is_string());
    BOOST_TEST(j["Users"][0]["Password"].get<std::string>().compare("password2") == 0);
    BOOST_TEST(j["Users"][0]["Fcm"]["Token"].is_string());
    BOOST_TEST(j["Users"][0]["Fcm"]["Token"].get<std::string>().compare("fcm_token") == 0);
    BOOST_TEST(j["Users"][0]["Fcm"]["ProjectId"].is_string());
    BOOST_TEST(j["Users"][0]["Fcm"]["ProjectId"].get<std::string>().compare("fcm_project") == 0);
    BOOST_TEST(j["Users"][0]["NotificationCategories"].is_array());
    BOOST_TEST(j["Users"][0]["NotificationCategories"][0].is_string());
    BOOST_TEST(j["Users"][0]["NotificationCategories"][0].get<std::string>().compare("cat1") == 0);
    BOOST_TEST(j["Users"][0]["NotificationCategories"][1].is_string());
    BOOST_TEST(j["Users"][0]["NotificationCategories"][1].get<std::string>().compare("cat2") == 0);
    nm_iam_state_free(state);
    nm_iam_serializer_string_free(jStr);
}

BOOST_AUTO_TEST_CASE(deserialize_config_from_json, *boost::unit_test::timeout(180))
{
    struct nm_iam_configuration* conf = nm_iam_configuration_new();
    BOOST_TEST(nm_iam_serializer_configuration_load_json(conf, c1.c_str(), NULL) == true);

    BOOST_TEST(strcmp(conf->unpairedRole, "TestRole") == 0);

    void* role;
    NN_LLIST_FOREACH(role, &conf->roles) {
        BOOST_TEST(strcmp(((struct nm_iam_role*)role)->id, "TestRole") == 0);
        const char* p;
        NN_STRING_SET_FOREACH(p, &((struct nm_iam_role*)role)->policies) {
            BOOST_TEST(strcmp(p, "TestPolicy") == 0);
        }
    }

    void* policy;
    NN_LLIST_FOREACH(policy, &conf->policies) {
        BOOST_REQUIRE_MESSAGE(strcmp(((struct nm_iam_policy*)policy)->id, "TestPolicy") == 0, ((struct nm_iam_policy*)policy)->id);
        void* stmt;
        NN_LLIST_FOREACH(stmt, &((struct nm_iam_policy*)policy)->statements) {
            BOOST_TEST(((struct nm_iam_statement*)stmt)->effect == NM_IAM_EFFECT_ALLOW);
            const char* a;
            NN_STRING_SET_FOREACH(a, &((struct nm_iam_statement*)stmt)->actions) {
                BOOST_TEST((strcmp(a, "Test:foo") == 0 || strcmp(a, "Test:bar") == 0) == true);
            }
            BOOST_TEST(nn_llist_empty(&((struct nm_iam_statement*)stmt)->conditions) == true);
        }
    }
    nm_iam_configuration_free(conf);
}

BOOST_AUTO_TEST_CASE(deserialize_state_from_json, *boost::unit_test::timeout(180))
{
    struct nm_iam_state* state = nm_iam_state_new();
    BOOST_TEST(nm_iam_serializer_state_load_json(state, s1.c_str(), NULL) == true);

    BOOST_TEST(strcmp(state->passwordOpenPassword, "password") == 0);
    BOOST_TEST(strcmp(state->passwordOpenSct, "token") == 0);

    void* user;
    NN_LLIST_FOREACH(user, &state->users) {
        BOOST_TEST(strcmp(((struct nm_iam_user*)user)->username, "username") == 0);
        BOOST_TEST(strcmp(((struct nm_iam_user*)user)->fingerprint, "fingerprint") == 0);
        BOOST_TEST(strcmp(((struct nm_iam_user*)user)->sct, "token2") == 0);
        BOOST_TEST(strcmp(((struct nm_iam_user*)user)->displayName, "Display Name") == 0);
        BOOST_TEST(strcmp(((struct nm_iam_user*)user)->role, "role1") == 0);
        BOOST_TEST(strcmp(((struct nm_iam_user*)user)->password, "password2") == 0);
        BOOST_TEST(strcmp(((struct nm_iam_user*)user)->fcmToken, "fcm_token") == 0);
        BOOST_TEST(strcmp(((struct nm_iam_user*)user)->fcmProjectId, "fcm_project") == 0);
        const char* p;
        bool cat1 = false; bool cat2 = false;
        NN_STRING_SET_FOREACH(p, &((struct nm_iam_user*)user)->notificationCategories) {
            if (strcmp(p, "cat1") == 0) {
                cat1 = true;
            } else if (strcmp(p, "cat2") == 0) {
                cat2 = true;
            } else {
                BOOST_CHECK_MESSAGE(false, "Unexpected notification category: " << p << " found");
            }
        }
        BOOST_TEST(cat1);
        BOOST_TEST(cat2);
    }
    nm_iam_state_free(state);
}

BOOST_AUTO_TEST_SUITE_END()
