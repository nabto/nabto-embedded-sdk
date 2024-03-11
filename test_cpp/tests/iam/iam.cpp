#include <boost/test/unit_test.hpp>

#include "iam_util.hpp"
#include "../spake2/spake2_util.hpp"
#include "../../util/helper.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_virtual.h>
#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>
#include <modules/iam/nm_iam_internal.h>
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
  "OpenPairingRole": "Admin",
  "InitialPairingUsername": "testuser",
  "LocalOpenPairing": true,
  "PasswordOpenPairing": true,
  "PasswordInvitePairing": true,
  "LocalInitialPairing": true,
  "Users": [
    {
      "DisplayName":"Display Name",
      "Fingerprints": [
        {
          "Fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "Name": "myphone"
        },
        {
          "Fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "Name": "yourphone"
        }
      ],
      "Role":"Admin",
      "Password":"password2",
      "Username":"testuser",
      "OauthSubject":"oauth_subject"
    }
  ],
  "Version":2
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
            "IAM:PairingPasswordOpen",
            "IAM:PairingPasswordInvite",
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

void doPwdAuth(NabtoDevice* d, struct nm_iam* iam, NabtoDeviceVirtualConnection* conn, const std::string username, const std::string clientFp, const std::string pwd) {

    nabto_device_virtual_connection_set_client_fingerprint(conn, clientFp.c_str());

    char* devFp = NULL;
    nabto_device_get_device_fingerprint(d, &devFp);
    BOOST_TEST((devFp != NULL));

    nabto_device_virtual_connection_set_device_fingerprint(conn, devFp);

    const std::string deviceFp(devFp);
    nabto_device_string_free(devFp);

    const char* auth1Path = "/p2p/pwd-auth/1";
    const char* auth2Path = "/p2p/pwd-auth/2";

    uint8_t clientFpBin[32];
    uint8_t deviceFpBin[32];

    nabto::test::fromHex(clientFp, clientFpBin);
    nabto::test::fromHex(deviceFp, deviceFpBin);
    // SETUP
    nabto::test::Spake2Client cli(pwd, clientFpBin, deviceFpBin);
    std::vector<uint8_t> T;
    BOOST_TEST(cli.calculateT(T) == 0);

    // AUTH REQ 1
    NabtoDeviceVirtualCoapRequest* req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_POST, auth1Path);

    BOOST_TEST((req != NULL));

    nlohmann::json root;
    root["Username"] = username;
    root["T"] = nlohmann::json::binary(T);

    auto payload = nlohmann::json::to_cbor(root);

    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(d);

    nabto_device_virtual_coap_request_execute(req, fut);

    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    // AUTH RESP 1
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 201);

    uint16_t cf;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_content_format(req, &cf) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(cf == NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM);

    uint8_t* respPayload;
    size_t len;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_payload(req, (void**)&respPayload, &len) == NABTO_DEVICE_EC_OK);


    BOOST_TEST(cli.calculateK(respPayload, len) == 0);
    BOOST_TEST(cli.calculateKey());
    std::array<uint8_t, 32> req2Key;
    BOOST_TEST(nabto::test::Spake2Client::sha256(cli.key_.data(), cli.key_.size(), req2Key.data()) == 0);

    std::array<uint8_t, 32> req2KeyHash;
    BOOST_TEST(nabto::test::Spake2Client::sha256(req2Key.data(), req2Key.size(), req2KeyHash.data()) == 0);

    nabto_device_virtual_coap_request_free(req);


    // AUTH REQ 2
    req = nabto_device_virtual_coap_request_new(conn, NABTO_DEVICE_COAP_POST, auth2Path);

    BOOST_TEST((req != NULL));

    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, req2KeyHash.data(), req2KeyHash.size()) == NABTO_DEVICE_EC_OK);

    nabto_device_virtual_coap_request_execute(req, fut);

    ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);

    // AUTH RESP 2
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 201);

    BOOST_TEST(nabto_device_virtual_coap_request_get_response_content_format(req, &cf) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(cf == NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_OCTET_STREAM);

    uint8_t* resp2Payload;
    size_t len2;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_payload(req, (void**)&resp2Payload, &len2) == NABTO_DEVICE_EC_OK);

    BOOST_TEST(memcmp(resp2Payload, req2Key.data(), req2Key.size()) == 0);
    nabto_device_virtual_coap_request_free(req);
    nabto_device_future_free(fut);
}

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

BOOST_AUTO_TEST_CASE(user_multi_fingerprint, *boost::unit_test::timeout(180))
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

    BOOST_TEST(!nm_iam_check_access(&iam, ref, "Admin:foo", NULL));

    nabto_device_virtual_connection_set_client_fingerprint(connection, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    BOOST_TEST(nm_iam_check_access(&iam, ref, "Admin:foo", NULL));

    nabto_device_virtual_connection_set_client_fingerprint(connection, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    BOOST_TEST(nm_iam_check_access(&iam, ref, "Admin:foo", NULL));

    nabto_device_virtual_connection_free(connection);

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

    nlohmann::json root;
    auto payload = nlohmann::json::to_cbor(root);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

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
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name != NULL);
            BOOST_CHECK(fp->fingerprint != NULL);
            if (strcmp(fp->name, "myphone") == 0) {
                BOOST_CHECK(strcmp(fp->fingerprint, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
            }
            else {
                BOOST_CHECK(strcmp(fp->fingerprint, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0);
                BOOST_CHECK(strcmp(fp->name, "yourphone") == 0);
            }

        }
        nm_iam_state_free(s);
    }
    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    NabtoDeviceConnectionRef ref = nabto_device_connection_get_connection_ref(connection);

    BOOST_TEST(nm_iam_authorize_connection(&iam, ref, "testuser") == NM_IAM_ERROR_OK);


    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/fingerprint");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    nlohmann::json root;
    auto payload = nlohmann::json::to_cbor(root);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

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
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name != NULL);
            BOOST_CHECK(fp->fingerprint != NULL);
            if (strcmp(fp->name, "myphone") == 0) {
                BOOST_CHECK(strcmp(fp->fingerprint, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
            }
            else {
                BOOST_CHECK(strcmp(fp->fingerprint, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0);
                BOOST_CHECK(strcmp(fp->name, "yourphone") == 0);
            }
        }
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(coap_add_fingerprint, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    NabtoDeviceConnectionRef ref = nabto_device_connection_get_connection_ref(connection);

    nabto_device_virtual_connection_set_client_fingerprint(connection, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/fingerprints/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    nlohmann::json root;
    root["FingerprintName"] = "mynewphone";
    auto payload = nlohmann::json::to_cbor(root);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

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
        bool found = false;
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name != NULL);
            if (strcmp(fp->name, "mynewphone") == 0) {
                found = true;
                BOOST_CHECK(strcmp(fp->fingerprint, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc") == 0);
            }
        }
        BOOST_CHECK(found);
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_set_client_fingerprint(connection, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

    BOOST_TEST(nm_iam_check_access(&iam, ref, "Admin:foo", NULL));

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(coap_add_fingerprint_noname, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    NabtoDeviceConnectionRef ref = nabto_device_connection_get_connection_ref(connection);

    nabto_device_virtual_connection_set_client_fingerprint(connection, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/fingerprints/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    nlohmann::json root;
    auto payload = nlohmann::json::to_cbor(root);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

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
        bool found = false;
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->fingerprint != NULL);
            if (strcmp(fp->fingerprint, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc") == 0) {
                found = true;
                BOOST_CHECK(fp->name == NULL);
            }
        }
        BOOST_CHECK(found);
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_set_client_fingerprint(connection, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

    BOOST_TEST(nm_iam_check_access(&iam, ref, "Admin:foo", NULL));

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(coap_delete_fingerprint, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    NabtoDeviceConnectionRef ref = nabto_device_connection_get_connection_ref(connection);

    nabto_device_virtual_connection_set_client_fingerprint(connection, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    BOOST_TEST(nm_iam_check_access(&iam, ref, "Admin:foo", NULL));

    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_DELETE, "/iam/users/testuser/fingerprints/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    BOOST_TEST((req != NULL));

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
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name != NULL);
            if (strcmp(fp->name, "myphone") == 0 || strcmp(fp->fingerprint, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc") == 0) {
                BOOST_CHECK(false);
            }
        }
        nm_iam_state_free(s);
    }

    BOOST_TEST(!nm_iam_check_access(&iam, ref, "Admin:foo", NULL));

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

    nlohmann::json root;
    auto payload = nlohmann::json::to_cbor(root);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

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

    nlohmann::json root;
    auto payload = nlohmann::json::to_cbor(root);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

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


BOOST_AUTO_TEST_CASE(pair_new_user, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);
    iam.usernameMaxLength = 10;

    enum nm_iam_error e = nm_iam_internal_pair_new_client(&iam, "_((;;.::)", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_INVALID_ARGUMENT);

    e = nm_iam_internal_pair_new_client(&iam, "abcdefghijkl", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_INVALID_ARGUMENT);

    e = nm_iam_internal_pair_new_client(&iam, NULL, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_INVALID_ARGUMENT);

    e = nm_iam_internal_pair_new_client(&iam, "myname", NULL, "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_INVALID_ARGUMENT);

    e = nm_iam_internal_pair_new_client(&iam, "testuser", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_USER_EXISTS);

    e = nm_iam_internal_pair_new_client(&iam, "newuser", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_USER_EXISTS);

    nm_iam_state_set_open_pairing_role(iam.state, NULL);
    e = nm_iam_internal_pair_new_client(&iam, "newname", "1111111111111111111111111111111111111111111111111111111111111111", "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_INTERNAL);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}


BOOST_AUTO_TEST_CASE(pwd_open_pairing, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    const std::string username = "";
    const std::string clientFp = "1234567890123456789012345678901212345678901234567890123456789012";
    std::string pwd(iam.state->passwordOpenPassword);

    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    nabto::test::doPwdAuth(d, &iam, connection, username, clientFp, pwd);


    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_POST, "/iam/pairing/password-open");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    nlohmann::json root;
    root["Username"] = "newuser";
    root["FingerprintName"] = "newphone";
    auto payload = nlohmann::json::to_cbor(root);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(d);
    nabto_device_virtual_coap_request_execute(req, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 201);
    nabto_device_virtual_coap_request_free(req);
    nabto_device_future_free(fut);


    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "newuser");
        BOOST_TEST((usr != NULL));
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name != NULL);
            BOOST_CHECK(fp->fingerprint != NULL);
            BOOST_TEST(strcmp(fp->name, "newphone") == 0);
            BOOST_TEST(strcmp(fp->fingerprint, clientFp.c_str()) == 0);
        }
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(pwd_open_pairing_no_fpname, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    const std::string username = "";
    const std::string clientFp = "1234567890123456789012345678901212345678901234567890123456789012";
    std::string pwd(iam.state->passwordOpenPassword);

    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    nabto::test::doPwdAuth(d, &iam, connection, username, clientFp, pwd);


    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_POST, "/iam/pairing/password-open");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    nlohmann::json root;
    root["Username"] = "newuser";
    auto payload = nlohmann::json::to_cbor(root);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(d);
    nabto_device_virtual_coap_request_execute(req, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 201);

    nabto_device_virtual_coap_request_free(req);
    nabto_device_future_free(fut);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "newuser");
        BOOST_TEST((usr != NULL));
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name == NULL);
            BOOST_CHECK(fp->fingerprint != NULL);
            BOOST_TEST(strcmp(fp->fingerprint, clientFp.c_str()) == 0);
        }
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(pwd_open_pairing_known_fp, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    const std::string username = "";
    const std::string clientFp = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    std::string pwd(iam.state->passwordOpenPassword);

    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    nabto::test::doPwdAuth(d, &iam, connection, username, clientFp, pwd);


    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_POST, "/iam/pairing/password-open");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    nlohmann::json root;
    root["Username"] = "newuser";
    root["FingerprintName"] = "newphone";
    auto payload = nlohmann::json::to_cbor(root);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(d);
    nabto_device_virtual_coap_request_execute(req, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 409);
    nabto_device_virtual_coap_request_free(req);
    nabto_device_future_free(fut);


    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "newuser");
        BOOST_TEST((usr == NULL));
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}



BOOST_AUTO_TEST_CASE(pwd_session_auth, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    const std::string username = "testuser";
    const std::string clientFp = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::string pwd = "password2";

    iam.state->passwordInvitePairing = false;

    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    nabto::test::doPwdAuth(d, &iam, connection, username, clientFp, pwd);

    NabtoDeviceConnectionRef ref = nabto_device_connection_get_connection_ref(connection);

    BOOST_TEST(nm_iam_check_access(&iam, ref, "Admin:foo", NULL));

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(pwd_invite_pairing, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    const std::string username = "testuser";
    const std::string clientFp = "1234567890123456789012345678901212345678901234567890123456789012";
    std::string pwd = "password2";

    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    nabto::test::doPwdAuth(d, &iam, connection, username, clientFp, pwd);


    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_POST, "/iam/pairing/password-invite");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    nlohmann::json root;
    root["FingerprintName"] = "newphone";
    auto payload = nlohmann::json::to_cbor(root);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(d);
    nabto_device_virtual_coap_request_execute(req, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 201);

    nabto_device_virtual_coap_request_free(req);
    nabto_device_future_free(fut);

    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name != NULL);
            BOOST_CHECK(fp->fingerprint != NULL);
            if (strcmp(fp->name, "myphone") == 0) {
                BOOST_CHECK(strcmp(fp->fingerprint, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
            }
            else if (strcmp(fp->name, "yourphone") == 0) {
                BOOST_CHECK(strcmp(fp->fingerprint, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0);
            }
            else {
                BOOST_TEST(strcmp(fp->name, "newphone") == 0);
                BOOST_TEST(strcmp(fp->fingerprint, clientFp.c_str()) == 0);
            }
        }
        BOOST_CHECK(usr->password == NULL);
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(pwd_invite_pairing_no_fpname, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);

    const std::string username = "testuser";
    const std::string clientFp = "1234567890123456789012345678901212345678901234567890123456789012";
    std::string pwd = "password2";

    NabtoDeviceVirtualConnection* connection = nabto_device_virtual_connection_new(d);

    nabto::test::doPwdAuth(d, &iam, connection, username, clientFp, pwd);


    auto req = nabto_device_virtual_coap_request_new(connection, NABTO_DEVICE_COAP_POST, "/iam/pairing/password-invite");

    BOOST_TEST((req != NULL));
    BOOST_TEST(nabto_device_virtual_coap_request_set_content_format(req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) == NABTO_DEVICE_EC_OK);

    nlohmann::json root;
    auto payload = nlohmann::json::to_cbor(root);
    BOOST_TEST(nabto_device_virtual_coap_request_set_payload(req, payload.data(), payload.size()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* fut = nabto_device_future_new(d);
    nabto_device_virtual_coap_request_execute(req, fut);
    NabtoDeviceError ec = nabto_device_future_wait(fut);
    BOOST_TEST(ec == NABTO_DEVICE_EC_OK);
    uint16_t status;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_status_code(req, &status) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(status == 201);
    nabto_device_virtual_coap_request_free(req);
    nabto_device_future_free(fut);


    {
        nm_iam_state* s = nm_iam_dump_state(&iam);
        struct nm_iam_user* usr = nm_iam_state_find_user_by_username(s, "testuser");
        BOOST_TEST((usr != NULL));
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            if (fp->name == NULL) {
                BOOST_TEST(strcmp(fp->fingerprint, clientFp.c_str()) == 0);
            } else {
                BOOST_CHECK(fp->fingerprint != NULL);
                if (strcmp(fp->name, "myphone") == 0) {
                    BOOST_CHECK(strcmp(fp->fingerprint, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
                } else {
                    BOOST_CHECK(strcmp(fp->fingerprint, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0);
                    BOOST_TEST(strcmp(fp->name, "yourphone") == 0);
                }

            }
        }
        BOOST_CHECK(usr->password == NULL);
        nm_iam_state_free(s);
    }

    nabto_device_virtual_connection_free(connection);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}



BOOST_AUTO_TEST_SUITE_END()
