#include <boost/test/unit_test.hpp>

#include "iam_util.hpp"
#include "../spake2/spake2_util.hpp"
#include "../../util/helper.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_virtual.h>
#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_user.h>
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
    },
    {
      "DisplayName":"Second Name",
      "Fingerprints": [],
      "Role":"Admin",
      "Password":"password3",
      "Username":"otheruser",
      "OauthSubject":"other_subject"
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

const std::string aFp = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const std::string bFp = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const std::string cFp = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

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
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);

    BOOST_TEST(!nm_iam_check_access(&ctx.iam_, ctx.ref_, "Admin:foo", NULL));

    nabto_device_virtual_connection_set_client_fingerprint(ctx.connection_, nabto::test::aFp.c_str());

    BOOST_TEST(nm_iam_check_access(&ctx.iam_, ctx.ref_, "Admin:foo", NULL));

    nabto_device_virtual_connection_set_client_fingerprint(ctx.connection_, nabto::test::bFp.c_str());

    BOOST_TEST(nm_iam_check_access(&ctx.iam_, ctx.ref_, "Admin:foo", NULL));
}

BOOST_AUTO_TEST_CASE(get_user_wellformed, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);

    BOOST_TEST(nm_iam_authorize_connection(&ctx.iam_, ctx.ref_, "testuser") == NM_IAM_ERROR_OK);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_GET, "/iam/users/testuser");
    nlohmann::json root;
    ctx.setCborPayload(root);
    ctx.executeCoap(205);

    uint16_t ct;
    nabto_device_virtual_coap_request_get_response_content_format(ctx.req_, &ct);
    BOOST_TEST(ct == NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);

    uint8_t* pl = NULL;
    size_t plLen;
    BOOST_TEST(nabto_device_virtual_coap_request_get_response_payload(ctx.req_, (void**)&pl, &plLen) == NABTO_DEVICE_EC_OK);

    BOOST_REQUIRE(pl != NULL);
    BOOST_REQUIRE(plLen > 0);

    std::vector<uint8_t> plVec(pl, pl+plLen);
    auto resp = nlohmann::json::from_cbor(plVec);

    BOOST_TEST(resp["DisplayName"].get<std::string>() == "Display Name");
    BOOST_TEST(resp["Fingerprint"].get<std::string>() == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    BOOST_TEST(resp["OauthSubject"].get<std::string>() == "oauth_subject");
    BOOST_TEST(resp["Role"].get<std::string>() == "Admin");
    BOOST_TEST(resp["Username"].get<std::string>() == "testuser");
    BOOST_TEST((resp["Fingerprints"].size() == 2));
    BOOST_TEST(resp["Fingerprints"][0]["Fingerprint"].get<std::string>() == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    BOOST_TEST(resp["Fingerprints"][0]["Name"].get<std::string>() == "myphone");
    BOOST_TEST(resp["Fingerprints"][1]["Fingerprint"].get<std::string>() == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    BOOST_TEST(resp["Fingerprints"][1]["Name"].get<std::string>() == "yourphone");
}

BOOST_AUTO_TEST_CASE(can_remove_displayname, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST(strcmp(usr->displayName, "Display Name") == 0);
        nm_iam_user_free(usr);
    }

    BOOST_TEST(nm_iam_authorize_connection(&ctx.iam_, ctx.ref_, "testuser") == NM_IAM_ERROR_OK);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/display-name");
    nlohmann::json root;
    ctx.setCborPayload(root);
    ctx.executeCoap(204);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        BOOST_CHECK(usr->displayName == NULL);
        nm_iam_user_free(usr);
    }
}

BOOST_AUTO_TEST_CASE(can_remove_fingerprint, *boost::unit_test::timeout(180))
{

    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name != NULL);
            BOOST_CHECK(fp->fingerprint != NULL);
            if (strcmp(fp->name, "myphone") == 0) {
                BOOST_CHECK(strcmp(fp->fingerprint, nabto::test::aFp.c_str()) == 0);
            }
            else {
                BOOST_CHECK(strcmp(fp->fingerprint, nabto::test::bFp.c_str()) == 0);
                BOOST_CHECK(strcmp(fp->name, "yourphone") == 0);
            }
        }
        nm_iam_user_free(usr);
    }
    BOOST_TEST(nm_iam_authorize_connection(&ctx.iam_, ctx.ref_, "testuser") == NM_IAM_ERROR_OK);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/fingerprint");
    nlohmann::json root;
    ctx.setCborPayload(root);
    ctx.executeCoap(204);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name != NULL);
            BOOST_CHECK(fp->fingerprint != NULL);
            if (strcmp(fp->name, "myphone") == 0 || strcmp(fp->fingerprint, nabto::test::aFp.c_str()) == 0) {
                BOOST_TEST(false);
            }
            else {
                BOOST_CHECK(strcmp(fp->fingerprint, nabto::test::bFp.c_str()) == 0);
                BOOST_CHECK(strcmp(fp->name, "yourphone") == 0);
            }
        }
        nm_iam_user_free(usr);
    }
}

BOOST_AUTO_TEST_CASE(coap_add_fingerprint, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);
    nabto_device_virtual_connection_set_client_fingerprint(ctx.connection_, nabto::test::aFp.c_str());

    std::string path = "/iam/users/testuser/fingerprints/" + nabto::test::cFp;
    ctx.createCoapRequest(NABTO_DEVICE_COAP_PUT, path);
    nlohmann::json root;
    root["FingerprintName"] = "mynewphone";
    ctx.setCborPayload(root);
    ctx.executeCoap(204);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        bool found = false;
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name != NULL);
            if (strcmp(fp->name, "mynewphone") == 0) {
                found = true;
                BOOST_CHECK(strcmp(fp->fingerprint, nabto::test::cFp.c_str()) == 0);
            }
        }
        BOOST_CHECK(found);
        nm_iam_user_free(usr);
    }

    nabto_device_virtual_connection_set_client_fingerprint(ctx.connection_, nabto::test::cFp.c_str());
    BOOST_TEST(nm_iam_check_access(&ctx.iam_, ctx.ref_, "Admin:foo", NULL));
}

BOOST_AUTO_TEST_CASE(coap_add_fingerprint_noname, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);
    nabto_device_virtual_connection_set_client_fingerprint(ctx.connection_, nabto::test::aFp.c_str());

    std::string path = "/iam/users/testuser/fingerprints/" + nabto::test::cFp;
    ctx.createCoapRequest(NABTO_DEVICE_COAP_PUT, path);
    nlohmann::json root;
    ctx.setCborPayload(root);
    ctx.executeCoap(204);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        bool found = false;
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->fingerprint != NULL);
            if (strcmp(fp->fingerprint, nabto::test::cFp.c_str()) == 0) {
                found = true;
                BOOST_CHECK(fp->name == NULL);
            }
        }
        BOOST_CHECK(found);
        nm_iam_user_free(usr);
    }

    nabto_device_virtual_connection_set_client_fingerprint(ctx.connection_, nabto::test::cFp.c_str());
    BOOST_TEST(nm_iam_check_access(&ctx.iam_, ctx.ref_, "Admin:foo", NULL));
}

BOOST_AUTO_TEST_CASE(coap_delete_fingerprint, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);
    nabto_device_virtual_connection_set_client_fingerprint(ctx.connection_, nabto::test::aFp.c_str());
    BOOST_TEST(nm_iam_check_access(&ctx.iam_, ctx.ref_, "Admin:foo", NULL));

    std::string path = "/iam/users/testuser/fingerprints/" + nabto::test::aFp;
    ctx.createCoapRequest(NABTO_DEVICE_COAP_DELETE, path);
    ctx.executeCoap(202);

    BOOST_TEST(!nm_iam_check_access(&ctx.iam_, ctx.ref_, "Admin:foo", NULL));

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name != NULL);
            BOOST_CHECK(fp->fingerprint != NULL);
            BOOST_TEST(strcmp(fp->fingerprint, nabto::test::aFp.c_str()) != 0);
        }
        nm_iam_user_free(usr);
    }

}

BOOST_AUTO_TEST_CASE(can_remove_oauth_sub, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);
    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST(strcmp(usr->oauthSubject, "oauth_subject") == 0);
        nm_iam_user_free(usr);
    }

    BOOST_TEST(nm_iam_authorize_connection(&ctx.iam_, ctx.ref_, "testuser") == NM_IAM_ERROR_OK);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/oauth-subject");
    nlohmann::json root;
    ctx.setCborPayload(root);
    ctx.executeCoap(204);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST((usr->oauthSubject == NULL));
        nm_iam_user_free(usr);
    }
}

BOOST_AUTO_TEST_CASE(can_remove_password, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST(strcmp(usr->password, "password2") == 0);
        nm_iam_user_free(usr);
    }

    BOOST_TEST(nm_iam_authorize_connection(&ctx.iam_, ctx.ref_, "testuser") == NM_IAM_ERROR_OK);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/password");
    nlohmann::json root;
    ctx.setCborPayload(root);
    ctx.executeCoap(204);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        BOOST_CHECK(usr->password == NULL);
        nm_iam_user_free(usr);
    }
}

BOOST_AUTO_TEST_CASE(enforce_min_password_len, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);
    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST(strcmp(usr->password, "password2") == 0);
        nm_iam_user_free(usr);
    }
    BOOST_TEST(nm_iam_authorize_connection(&ctx.iam_, ctx.ref_, "testuser") == NM_IAM_ERROR_OK);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_PUT, "/iam/users/testuser/password");
    nlohmann::json root = "123";
    ctx.setCborPayload(root);
    ctx.executeCoap(400);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST(strcmp(usr->password, "password2") == 0);
        nm_iam_user_free(usr);
    }
}


BOOST_AUTO_TEST_CASE(pair_new_user, *boost::unit_test::timeout(180))
{
    struct nm_iam iam;
    NabtoDevice* d = nabto::test::buildIamTestDevice(nabto::test::c2, nabto::test::s2, &iam);
    iam.usernameMaxLength = 10;

    enum nm_iam_error e = nm_iam_internal_pair_new_client(&iam, "_((;;.::)", nabto::test::aFp.c_str(), "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_INVALID_ARGUMENT);

    e = nm_iam_internal_pair_new_client(&iam, "abcdefghijkl", nabto::test::aFp.c_str(), "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_INVALID_ARGUMENT);

    e = nm_iam_internal_pair_new_client(&iam, NULL, nabto::test::aFp.c_str(), "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_INVALID_ARGUMENT);

    e = nm_iam_internal_pair_new_client(&iam, "myname", NULL, "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_INVALID_ARGUMENT);

    e = nm_iam_internal_pair_new_client(&iam, "testuser3", nabto::test::aFp.c_str(), "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_USER_EXISTS);

    e = nm_iam_internal_pair_new_client(&iam, "testuser", nabto::test::aFp.c_str(), "myphone");
    BOOST_TEST(e == NM_IAM_ERROR_OK);

    e = nm_iam_internal_pair_new_client(&iam, "newuser", nabto::test::aFp.c_str(), "myphone");
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
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);
    const std::string username = "";
    const std::string clientFp = "1234567890123456789012345678901212345678901234567890123456789012";
    std::string pwd(ctx.iam_.state->passwordOpenPassword);

    ctx.doPwdAuth(username, clientFp, pwd);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_POST, "/iam/pairing/password-open");
    nlohmann::json root;
    root["Username"] = "newuser";
    root["FingerprintName"] = "newphone";
    ctx.setCborPayload(root);
    ctx.executeCoap(201);

    {
        auto usr = ctx.findStateUser("newuser");
        BOOST_TEST((usr != NULL));
        bool found = false;
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name != NULL);
            BOOST_TEST(strcmp(fp->name, "newphone") == 0);
            BOOST_CHECK(fp->fingerprint != NULL);
            BOOST_CHECK(strcmp(fp->fingerprint, clientFp.c_str()) == 0);
            found = true;
        }
        BOOST_CHECK(found);
        nm_iam_user_free(usr);
    }
}

BOOST_AUTO_TEST_CASE(pwd_open_pairing_no_fpname, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);
    const std::string username = "";
    const std::string clientFp = "1234567890123456789012345678901212345678901234567890123456789012";
    std::string pwd(ctx.iam_.state->passwordOpenPassword);

    ctx.doPwdAuth(username, clientFp, pwd);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_POST, "/iam/pairing/password-open");
    nlohmann::json root;
    root["Username"] = "newuser";
    ctx.setCborPayload(root);
    ctx.executeCoap(201);

    {
        auto usr = ctx.findStateUser("newuser");
        BOOST_TEST((usr != NULL));
        bool found = false;
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->name == NULL);
            BOOST_CHECK(fp->fingerprint != NULL);
            BOOST_CHECK(strcmp(fp->fingerprint, clientFp.c_str()) == 0);
            found = true;
        }
        BOOST_CHECK(found);
        nm_iam_user_free(usr);
    }
}

BOOST_AUTO_TEST_CASE(pwd_open_pairing_known_fp, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);
    const std::string username = "";
    std::string pwd(ctx.iam_.state->passwordOpenPassword);

    ctx.doPwdAuth(username, nabto::test::bFp, pwd);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_POST, "/iam/pairing/password-open");
    nlohmann::json root;
    root["Username"] = "newuser";
    root["FingerprintName"] = "newphone";
    ctx.setCborPayload(root);
    ctx.executeCoap(409);

    {
        auto usr = ctx.findStateUser("newuser");
        BOOST_TEST((usr == NULL));
    }
}



BOOST_AUTO_TEST_CASE(pwd_session_auth, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);

    const std::string username = "testuser";
    std::string pwd = "password2";

    ctx.iam_.state->passwordInvitePairing = false;

    ctx.doPwdAuth(username, nabto::test::aFp, pwd);

    BOOST_TEST(nm_iam_check_access(&ctx.iam_, ctx.ref_, "Admin:foo", NULL));
}

BOOST_AUTO_TEST_CASE(pwd_invite_pairing, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);
    const std::string username = "testuser";
    const std::string clientFp = "1234567890123456789012345678901212345678901234567890123456789012";
    std::string pwd = "password2";

    ctx.doPwdAuth(username, clientFp, pwd);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_POST, "/iam/pairing/password-invite");
    nlohmann::json root;
    root["FingerprintName"] = "newphone";
    ctx.setCborPayload(root);
    ctx.executeCoap(201);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        bool found = false;
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
                found = true;
            }
        }
        BOOST_CHECK(found);
        BOOST_CHECK(usr->password == NULL);
        nm_iam_user_free(usr);
    }
}

BOOST_AUTO_TEST_CASE(pwd_invite_pairing_no_fpname, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);
    const std::string username = "testuser";
    const std::string clientFp = "1234567890123456789012345678901212345678901234567890123456789012";
    std::string pwd = "password2";

    ctx.doPwdAuth(username, clientFp, pwd);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_POST, "/iam/pairing/password-invite");
    nlohmann::json root;
    ctx.setCborPayload(root);
    ctx.executeCoap(201);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        bool found = false;
        void* f;
        NN_LLIST_FOREACH(f, &usr->fingerprints) {
            struct nm_iam_user_fingerprint* fp = (struct nm_iam_user_fingerprint*)f;
            BOOST_CHECK(fp->fingerprint != NULL);
            if (strcmp(fp->fingerprint, nabto::test::aFp.c_str()) == 0) {
                BOOST_CHECK(fp->name != NULL);
                BOOST_CHECK(strcmp(fp->name, "myphone") == 0);
            }
            else if (strcmp(fp->fingerprint, nabto::test::bFp.c_str()) == 0) {
                BOOST_CHECK(fp->name != NULL);
                BOOST_CHECK(strcmp(fp->name, "yourphone") == 0);
            }
            else {
                BOOST_CHECK(fp->name == NULL);
                BOOST_TEST(strcmp(fp->fingerprint, clientFp.c_str()) == 0);
                found = true;
            }
        }
        BOOST_CHECK(found);
        BOOST_CHECK(usr->password == NULL);
        nm_iam_user_free(usr);
    }
}

BOOST_AUTO_TEST_CASE(pwd_invite_pairing_conflict, *boost::unit_test::timeout(180))
{
    nabto::test::IamVirtualConnTester ctx(nabto::test::c2, nabto::test::s2);
    const std::string username = "testuser";
    const std::string username2 = "otheruser";
    const std::string clientFp = "1234567890123456789012345678901212345678901234567890123456789012";
    std::string pwd = "password2";
    std::string pwd2 = "password3";

    ctx.doPwdAuth(username, clientFp, pwd);

    ctx.createCoapRequest(NABTO_DEVICE_COAP_POST, "/iam/pairing/password-invite");
    nlohmann::json root;
    root["FingerprintName"] = "newphone";
    ctx.setCborPayload(root);
    ctx.executeCoap(201);

    ctx.doPwdAuth(username2, clientFp, pwd2);
    ctx.setCborPayload(root);
    ctx.executeCoap(409);

    {
        auto usr = ctx.findStateUser("testuser");
        BOOST_TEST((usr != NULL));
        bool found = false;
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
                found = true;
            }
        }
        BOOST_CHECK(found);
        BOOST_CHECK(usr->password == NULL);
        nm_iam_user_free(usr);
    }
    {
        auto usr = ctx.findStateUser("otheruser");
        BOOST_TEST((usr != NULL));
        BOOST_TEST((nn_llist_empty(&usr->fingerprints) == true));
        nm_iam_user_free(usr);
    }
}



BOOST_AUTO_TEST_SUITE_END()
