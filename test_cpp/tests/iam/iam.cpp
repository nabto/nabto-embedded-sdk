#include <boost/test/unit_test.hpp>

#include "iam_util.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_virtual.h>
#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>
#include <nn/string_set.h>

#include <platform/np_allocator.h>

#include <nlohmann/json.hpp>
#include <iomanip>

namespace nabto {
namespace test {


std::string s2 = R"(
{
  "OpenPairingPassword":"password",
  "OpenPairingSct":"token",
  "FriendlyName":"Friendly Name",
  "Users": [
    {
      "DisplayName":"Display Name",
      "Fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "Role":"Admin",
      "Password":"password2",
      "Username":"testuser",
      "OauthSubject":"oauth_subject"
    }
  ],
  "Version":1
}
)";

std::string c2 = R"(
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
    },
    {
      "Id":"AdminPolicy",
      "Statements": [
        {
          "Actions":[
            "Admin:foo",
            "Admin:bar"
          ],
          "Effect":"Allow"
        }
      ]
    },
    {
      "Id":"IamUsers",
      "Statements": [
        {
          "Actions":[
            "IAM:ListUsers",
            "IAM:GetUser",
            "IAM:DeleteUser",
            "IAM:SetUserRole",
            "IAM:ListRoles",
            "IAM:CreateUser",
            "IAM:SetUserPassword",
            "IAM:SetUserFingerprint",
            "IAM:SetUserDisplayName",
            "IAM:SetUserOauthSubject",
            "IAM:SetSettings",
            "IAM:GetSettings"
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
    },
    {
      "Id":"Admin",
      "Policies":[
        "TestPolicy",
        "AdminPolicy",
        "IamUsers"
      ]
    }

  ],
  "Version":1
}
)";

}
} // namespaces

BOOST_AUTO_TEST_SUITE(iam)

BOOST_AUTO_TEST_CASE(set_notification_categories, *boost::unit_test::timeout(180))
{
    NabtoDevice* d = nabto_device_new();
    const char* logLevel = getenv("NABTO_LOG_LEVEL");
    if (logLevel != NULL) {
        nabto_device_set_log_level(d, logLevel);
        nabto_device_set_log_std_out_callback(d);
    }
    struct nm_iam iam;
    nm_iam_init(&iam, d, NULL);
    struct nn_string_set cats;
    nn_string_set_init(&cats, np_allocator_get());
    nn_string_set_insert(&cats, "cat1");
    nn_string_set_insert(&cats, "cat2");
    BOOST_TEST(nm_iam_set_notification_categories(&iam, &cats) == NM_IAM_ERROR_OK);
    nn_string_set_deinit(&cats);

    BOOST_TEST(nn_string_set_contains(&iam.notificationCategories, "cat1"));
    BOOST_TEST(nn_string_set_contains(&iam.notificationCategories, "cat2"));

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(expire_auth_on_close, *boost::unit_test::timeout(180))
{
    NabtoDevice* d = nabto_device_new();
    struct nn_log iamLogger;
    iamLogger.logPrint = &nabto::test::iam_logger;

    const char* logLevel = getenv("NABTO_LOG_LEVEL");
    if (logLevel != NULL) {
        nabto_device_set_log_level(d, logLevel);
        nabto_device_set_log_std_out_callback(d);
    }
    struct nm_iam iam;
    nm_iam_init(&iam, d, &iamLogger);

    struct nm_iam_configuration* conf = nm_iam_configuration_new();
    BOOST_TEST(nm_iam_serializer_configuration_load_json(conf, nabto::test::c2.c_str(), NULL) == true);

    struct nm_iam_state* state = nm_iam_state_new();
    BOOST_TEST(nm_iam_serializer_state_load_json(state, nabto::test::s2.c_str(), NULL) == true);

    BOOST_TEST(nm_iam_load_configuration(&iam, conf));
    BOOST_TEST(nm_iam_load_state(&iam, state));

    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    NabtoDeviceConnectionRef ref = nabto_device_connection_get_connection_ref(connection);

    nm_iam_lock(&iam);
    BOOST_TEST((nn_vector_size(&iam.authorizedConnections) == 0));
    nm_iam_unlock(&iam);

    BOOST_TEST(!nm_iam_check_access(&iam, ref, "Admin:foo", NULL));

    BOOST_TEST(nm_iam_authorize_connection(&iam, ref, "testuser") == NM_IAM_ERROR_OK);

    nm_iam_lock(&iam);
    BOOST_TEST((nn_vector_size(&iam.authorizedConnections) == 1));
    nm_iam_unlock(&iam);

    BOOST_TEST(nm_iam_check_access(&iam, ref, "Admin:foo", NULL));


    nabto_device_virtual_connection_free(connection);

    // This IAM check fails because the reference is invalid, not because it was cleaned up
    BOOST_TEST(!nm_iam_check_access(&iam, ref, "Admin:foo", NULL));


    // This test fails most of the time because we do not have a good way of making the test wait for the connection event to reach the IAM module, and for the module to handle the event.
    // nm_iam_lock(&iam);
    // BOOST_TEST((nn_vector_size(&iam.authorizedConnections) == 0));
    // nm_iam_unlock(&iam);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(can_remove_displayname, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST(strcmp(usr->displayName, "Display Name") == 0);
        nm_iam_state_free(s);
    }
    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    NabtoDeviceConnectionRef ref = nabto_device_connection_get_connection_ref(connection);

    BOOST_TEST(nm_iam_authorize_connection(&iam, ref, "testuser") == NM_IAM_ERROR_OK);


    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/display-name");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    uint8_t payload[1];
    payload[0] = 0xF6;

    std::cout << std::endl;
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload, 1) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(d);
    nabto_device_virtual_coap_request_execute(req, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 204);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST((usr->displayName == NULL));
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(can_remove_fingerprint, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST(strcmp(usr->fingerprint, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
        nm_iam_state_free(s);
    }
    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    NabtoDeviceConnectionRef ref = nabto_device_connection_get_connection_ref(connection);

    BOOST_TEST(nm_iam_authorize_connection(&iam, ref, "testuser") == NM_IAM_ERROR_OK);


    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/fingerprint");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    uint8_t payload[1];
    payload[0] = 0xF6;

    std::cout << std::endl;
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload, 1) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(d);
    nabto_device_virtual_coap_request_execute(req, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 204);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST((usr->fingerprint == NULL));
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(can_remove_oauth_sub, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST(strcmp(usr->oauthSubject, "oauth_subject") == 0);
        nm_iam_state_free(s);
    }
    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    NabtoDeviceConnectionRef ref = nabto_device_connection_get_connection_ref(connection);

    BOOST_TEST(nm_iam_authorize_connection(&iam, ref, "testuser") == NM_IAM_ERROR_OK);


    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/oauth-subject");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    uint8_t payload[1];
    payload[0] = 0xF6;

    std::cout << std::endl;
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload, 1) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(d);
    nabto_device_virtual_coap_request_execute(req, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 204);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST((usr->oauthSubject == NULL));
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(can_remove_password, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST(strcmp(usr->password, "password2") == 0);
        nm_iam_state_free(s);
    }
    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    NabtoDeviceConnectionRef ref = nabto_device_connection_get_connection_ref(connection);

    BOOST_TEST(nm_iam_authorize_connection(&iam, ref, "testuser") == NM_IAM_ERROR_OK);


    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/password");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    uint8_t payload[1];
    payload[0] = 0xF6;

    std::cout << std::endl;
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload, 1) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(d);
    nabto_device_virtual_coap_request_execute(req, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 204);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST((usr->password == NULL));
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(enforce_min_password_len, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST(strcmp(usr->password, "password2") == 0);
        nm_iam_state_free(s);
    }
    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    NabtoDeviceConnectionRef ref = nabto_device_connection_get_connection_ref(connection);

    BOOST_TEST(nm_iam_authorize_connection(&iam, ref, "testuser") == NM_IAM_ERROR_OK);


    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/password");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    nlohmann::json root = "123";
    auto payload = nlohmann::json::to_cbor(root);

    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(d);
    nabto_device_virtual_coap_request_execute(req, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 400);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST(strcmp(usr->password, "password2") == 0);
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}


BOOST_AUTO_TEST_SUITE_END()
