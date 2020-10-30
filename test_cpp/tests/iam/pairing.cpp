#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>

#include <nlohmann/json.hpp>

BOOST_AUTO_TEST_SUITE(iam)

BOOST_AUTO_TEST_CASE(dump_config_as_json, *boost::unit_test::timeout(180))
{
    NabtoDevice* device = nabto_device_new();
    struct nm_iam iam;
    nm_iam_init(&iam, device, NULL);

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
        nm_iam_configuration_set_first_user_role(conf, "TestRole");
    }

    char* iamConf;
    BOOST_TEST(nm_iam_serializer_configuration_dump_json(conf, &iamConf));

    nlohmann::json j = nlohmann::json::parse(iamConf);
    BOOST_TEST(j["Config"].is_object());
    BOOST_TEST(j["Config"]["FirstUserRole"].is_string());
    BOOST_TEST(j["Config"]["FirstUserRole"].get<std::string>().compare("TestRole") == 0);

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
    nabto_device_stop(device);
    nm_iam_deinit(&iam);
    nabto_device_free(device);
}

BOOST_AUTO_TEST_SUITE_END();
