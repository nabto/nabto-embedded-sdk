#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <modules/iam/nm_iam_user.h>
#include <modules/iam/nm_iam_serializer.h>
#include <nn/llist.h>
#include <nn/string_set.h>
#include <nlohmann/json.hpp>

#include <platform/np_allocator.h>

namespace nabto {
namespace test {

void iam_logger(void* data, enum nn_log_severity severity, const char* module,
                const char* file, int line,
                const char* fmt, va_list args)
{
    (void)data; (void)module;
    const char* logLevelCStr = getenv("NABTO_LOG_LEVEL");
    if(logLevelCStr == NULL) { return; }
    std::string logLevelStr(logLevelCStr);
    if ((logLevelStr.compare("error") == 0 && severity <= NN_LOG_SEVERITY_ERROR) ||
        (logLevelStr.compare("warn") == 0 && severity <= NN_LOG_SEVERITY_WARN) ||
        (logLevelStr.compare("info") == 0 && severity <= NN_LOG_SEVERITY_INFO) ||
        (logLevelStr.compare("trace") == 0 && severity <= NN_LOG_SEVERITY_TRACE)
        ) {
        char log[256];
        int ret;

        ret = vsnprintf(log, 256, fmt, args);
        if (ret >= 256) {
            // The log line was too large for the array
        }
        size_t fileLen = strlen(file);
        char fileTmp[16+4];
        if(fileLen > 16) {
            strcpy(fileTmp, "...");
            strcpy(fileTmp + 3, file + fileLen - 16);
        } else {
            strcpy(fileTmp, file);
        }
        const char* level;
        switch(severity) {
            case NN_LOG_SEVERITY_ERROR:
                level = "ERROR";
                break;
            case NN_LOG_SEVERITY_WARN:
                level = "_WARN";
                break;
            case NN_LOG_SEVERITY_INFO:
                level = "_INFO";
                break;
            case NN_LOG_SEVERITY_TRACE:
                level = "TRACE";
                break;
            default:
                // should not happen as it would be caugth by the if
                level = "_NONE";
                break;
        }

        printf("%s(%03u)[%s] %s\n",
               fileTmp, line, level, log);

    }
}

struct nm_iam_state* initState()
{
    struct nm_iam_state* state = nm_iam_state_new();
    nm_iam_state_set_password_open_password(state, "password");
    nm_iam_state_set_password_open_sct(state, "token");
    nm_iam_state_set_password_open_pairing(state, true);
    nm_iam_state_set_local_open_pairing(state, true);
    nm_iam_state_set_password_invite_pairing(state, true);
    nm_iam_state_set_local_initial_pairing(state, true);
    nm_iam_state_set_open_pairing_role(state, "role1");
    nm_iam_state_set_initial_pairing_username(state, "username");
    nm_iam_state_set_friendly_name(state, "friendly name");

    struct nm_iam_user* usr = nm_iam_state_user_new("username");
    nm_iam_state_user_set_fingerprint(usr, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    nm_iam_state_user_set_sct(usr, "token2");
    nm_iam_state_user_set_display_name(usr, "Display Name");
    nm_iam_state_user_set_role(usr, "role1");
    nm_iam_state_user_set_password(usr, "password2");
    nm_iam_state_user_set_fcm_token(usr, "fcm_token");
    nm_iam_state_user_set_fcm_project_id(usr, "fcm_project");
    struct nn_string_set cats;
    nn_string_set_init(&cats, np_allocator_get());
    nn_string_set_insert(&cats, "cat1");
    nn_string_set_insert(&cats, "cat2");
    nm_iam_state_user_set_notification_categories(usr, &cats);
    nn_string_set_deinit(&cats);
    nm_iam_state_add_user(state, usr);
    return state;
}

std::string s1 = R"(
{
  "OpenPairingPassword":"password",
  "OpenPairingSct":"token",
  "FriendlyName":"Friendly Name",
  "Users": [
    {
      "DisplayName":"Display Name",
      "Fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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

} } // namespaces

BOOST_AUTO_TEST_SUITE(iam)

BOOST_AUTO_TEST_CASE(load_dump_state, *boost::unit_test::timeout(180))
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

    struct nm_iam_state* state = nabto::test::initState();
    struct nn_string_set cats;
    nn_string_set_init(&cats, np_allocator_get());
    nn_string_set_insert(&cats, "cat1");
    nn_string_set_insert(&cats, "cat2");
    BOOST_REQUIRE(nm_iam_set_notification_categories(&iam, &cats) == NM_IAM_ERROR_OK);
    nn_string_set_deinit(&cats);
    BOOST_REQUIRE(nm_iam_load_state(&iam, state));
    struct nm_iam_state* dump = nm_iam_dump_state(&iam);

    // state is now owned by the iam module, however, we know the
    // device does nothing, so we keep use it as reference.
    BOOST_CHECK(strcmp(state->passwordOpenPassword, dump->passwordOpenPassword) == 0);
    BOOST_CHECK(strcmp(state->passwordOpenSct, dump->passwordOpenSct) == 0);
    BOOST_CHECK(state->passwordOpenPairing == dump->passwordOpenPairing);
    BOOST_CHECK(state->localOpenPairing == dump->localOpenPairing);
    BOOST_CHECK(state->passwordInvitePairing == dump->passwordInvitePairing);
    BOOST_CHECK(state->localInitialPairing == dump->localInitialPairing);
    BOOST_CHECK(strcmp(state->openPairingRole, dump->openPairingRole) == 0);
    BOOST_CHECK(strcmp(state->initialPairingUsername, dump->initialPairingUsername) == 0);
    BOOST_CHECK(strcmp(state->friendlyName, dump->friendlyName) == 0);

    BOOST_TEST(nn_llist_size(&dump->users) == (size_t)1);
    void* u;
    NN_LLIST_FOREACH(u, &dump->users) {
        struct nm_iam_user* user = (struct nm_iam_user*)u;
        BOOST_CHECK(strcmp(user->username, "username") == 0);
        BOOST_CHECK(strcmp(user->displayName, "Display Name") == 0);
        BOOST_CHECK(strcmp(user->role, "role1") == 0);
        BOOST_CHECK(strcmp(user->password, "password2") == 0);
        BOOST_CHECK(strcmp(user->fingerprint, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
        BOOST_CHECK(strcmp(user->sct, "token2") == 0);
        BOOST_CHECK(strcmp(user->fcmToken, "fcm_token") == 0);
        BOOST_CHECK(strcmp(user->fcmProjectId, "fcm_project") == 0);
        BOOST_CHECK(nn_string_set_contains(&user->notificationCategories, "cat1"));
        BOOST_CHECK(nn_string_set_contains(&user->notificationCategories, "cat2"));
    }
    nm_iam_state_free(dump);
    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(runtime_create_user, *boost::unit_test::timeout(180))
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
    nn_string_set_insert(&cats, "cat42");
    nn_string_set_insert(&cats, "cat43");
    BOOST_REQUIRE(nm_iam_set_notification_categories(&iam, &cats) == NM_IAM_ERROR_OK);
    nn_string_set_deinit(&cats);

    struct nm_iam_state* state = nabto::test::initState();
    BOOST_REQUIRE(nm_iam_load_state(&iam, state));

    BOOST_CHECK(nm_iam_create_user(&iam, "newuser") == NM_IAM_ERROR_OK);
    BOOST_TEST(nm_iam_set_user_fingerprint(&iam, "newuser", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == NM_IAM_ERROR_OK);
    BOOST_CHECK(nm_iam_set_user_sct(&iam, "newuser", "token42") == NM_IAM_ERROR_OK);
    BOOST_CHECK(nm_iam_set_user_password(&iam, "newuser", "password42") == NM_IAM_ERROR_OK);
    BOOST_CHECK(nm_iam_set_user_role(&iam, "newuser", "role42") == NM_IAM_ERROR_NO_SUCH_ROLE);
    BOOST_CHECK(nm_iam_set_user_display_name(&iam, "newuser", "New Display Name") == NM_IAM_ERROR_OK);
    BOOST_CHECK(nm_iam_set_user_fcm_token(&iam, "newuser", "fcm_token_42") == NM_IAM_ERROR_OK);
    BOOST_CHECK(nm_iam_set_user_fcm_project_id(&iam, "newuser", "fcm_project_42") == NM_IAM_ERROR_OK);
    nn_string_set_init(&cats, np_allocator_get());
    nn_string_set_insert(&cats, "cat42");
    nn_string_set_insert(&cats, "cat43");
    BOOST_CHECK(nm_iam_set_user_notification_categories(&iam, "newuser", &cats) == NM_IAM_ERROR_OK);
    nn_string_set_deinit(&cats);

    struct nm_iam_state* dump = nm_iam_dump_state(&iam);

    BOOST_TEST(nn_llist_size(&dump->users) == (size_t)2);
    void* u;
    bool found = false;
    NN_LLIST_FOREACH(u, &dump->users) {
        struct nm_iam_user* user = (struct nm_iam_user*)u;
        if (strcmp(user->username, "newuser") == 0) {
            found = true;
            BOOST_CHECK(strcmp(user->username, "newuser") == 0);
            BOOST_CHECK(strcmp(user->displayName, "New Display Name") == 0);
            BOOST_CHECK(user->role == NULL);
            BOOST_CHECK(strcmp(user->password, "password42") == 0);
            BOOST_CHECK(strcmp(user->fingerprint, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0);
            BOOST_CHECK(strcmp(user->sct, "token42") == 0);
            BOOST_CHECK(strcmp(user->fcmToken, "fcm_token_42") == 0);
            BOOST_CHECK(strcmp(user->fcmProjectId, "fcm_project_42") == 0);
            BOOST_CHECK(nn_string_set_contains(&user->notificationCategories, "cat42"));
            BOOST_CHECK(nn_string_set_contains(&user->notificationCategories, "cat43"));
        }
    }
    BOOST_CHECK(found);
    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nm_iam_state_free(dump);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(empty_username_is_invalid, *boost::unit_test::timeout(180))
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
    BOOST_REQUIRE(nm_iam_set_notification_categories(&iam, &cats) == NM_IAM_ERROR_OK);
    nn_string_set_deinit(&cats);

    struct nm_iam_state* state = nabto::test::initState();
    BOOST_REQUIRE(nm_iam_load_state(&iam, state));

    BOOST_CHECK(nm_iam_create_user(&iam, "") == NM_IAM_ERROR_INVALID_ARGUMENT);
    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(username_is_invalid, *boost::unit_test::timeout(180))
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
    BOOST_REQUIRE(nm_iam_set_notification_categories(&iam, &cats) == NM_IAM_ERROR_OK);
    nn_string_set_deinit(&cats);

    struct nm_iam_state* state = nabto::test::initState();
    BOOST_REQUIRE(nm_iam_load_state(&iam, state));

    BOOST_TEST(nm_iam_create_user(&iam, "Foobar") == NM_IAM_ERROR_INVALID_ARGUMENT);
    BOOST_TEST(nm_iam_create_user(&iam, "foo=bar") == NM_IAM_ERROR_INVALID_ARGUMENT);
    BOOST_TEST(nm_iam_create_user(&iam, " foobar") == NM_IAM_ERROR_INVALID_ARGUMENT);
    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(runtime_delete_user, *boost::unit_test::timeout(180))
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
    BOOST_REQUIRE(nm_iam_set_notification_categories(&iam, &cats) == NM_IAM_ERROR_OK);
    nn_string_set_deinit(&cats);

    struct nm_iam_state* state = nabto::test::initState();
    BOOST_REQUIRE(nm_iam_load_state(&iam, state));

    nm_iam_delete_user(&iam, "username");

    struct nm_iam_state* dump = nm_iam_dump_state(&iam);

    BOOST_TEST(nn_llist_size(&dump->users) == (size_t)0);
    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nm_iam_state_free(dump);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(load_with_limits, *boost::unit_test::timeout(180))
{
    NabtoDevice* d = nabto_device_new();
    const char* logLevel = getenv("NABTO_LOG_LEVEL");
    if (logLevel != NULL) {
        nabto_device_set_log_level(d, logLevel);
        nabto_device_set_log_std_out_callback(d);
    }
    struct nm_iam iam;
    nm_iam_init(&iam, d, NULL);

    struct nm_iam_state* state = nabto::test::initState();
    struct nn_string_set cats;
    nn_string_set_init(&cats, np_allocator_get());
    nn_string_set_insert(&cats, "cat1");
    nn_string_set_insert(&cats, "cat2");
    BOOST_REQUIRE(nm_iam_set_notification_categories(&iam, &cats) == NM_IAM_ERROR_OK);
    nn_string_set_deinit(&cats);

    nm_iam_set_username_max_length(&iam, 2);
    BOOST_TEST(!nm_iam_load_state(&iam, state));
    nm_iam_set_username_max_length(&iam, 64);

    nm_iam_set_display_name_max_length(&iam, 2);
    BOOST_TEST(!nm_iam_load_state(&iam, state));
    nm_iam_set_display_name_max_length(&iam, 64);

    nm_iam_set_password_max_length(&iam, 2);
    BOOST_TEST(!nm_iam_load_state(&iam, state));
    nm_iam_set_password_max_length(&iam, 64);

    nm_iam_set_fcm_token_max_length(&iam, 2);
    BOOST_TEST(!nm_iam_load_state(&iam, state));
    nm_iam_set_fcm_token_max_length(&iam, 1024);

    nm_iam_set_fcm_project_id_max_length(&iam, 2);
    BOOST_TEST(!nm_iam_load_state(&iam, state));
    nm_iam_set_fcm_project_id_max_length(&iam, 64);

    nm_iam_set_sct_max_length(&iam, 2);
    BOOST_TEST(!nm_iam_load_state(&iam, state));
    nm_iam_set_sct_max_length(&iam, 64);

    nm_iam_set_max_users(&iam, 0);
    BOOST_TEST(!nm_iam_load_state(&iam, state));
    nm_iam_set_max_users(&iam, 64);

    nm_iam_set_friendly_name_max_length(&iam, 2);
    BOOST_TEST(!nm_iam_load_state(&iam, state));
    nm_iam_set_friendly_name_max_length(&iam, 64);

    BOOST_TEST(nm_iam_load_state(&iam, state));

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}

BOOST_AUTO_TEST_CASE(runtime_limits, *boost::unit_test::timeout(180))
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
    BOOST_REQUIRE(nm_iam_set_notification_categories(&iam, &cats) == NM_IAM_ERROR_OK);
    nn_string_set_deinit(&cats);

    nm_iam_set_username_max_length(&iam, 12);
    nm_iam_set_display_name_max_length(&iam, 12);
    nm_iam_set_password_max_length(&iam, 12);
    nm_iam_set_fcm_token_max_length(&iam, 12);
    nm_iam_set_fcm_project_id_max_length(&iam, 12);
    nm_iam_set_sct_max_length(&iam, 12);
    nm_iam_set_max_users(&iam, 1);

    struct nm_iam_state* state = nabto::test::initState();
    BOOST_REQUIRE(nm_iam_load_state(&iam, state));

    BOOST_TEST(nm_iam_create_user(&iam, "abcde") == NM_IAM_ERROR_INTERNAL); // user limit
    BOOST_TEST(nm_iam_create_user(&iam, "abcdefghijklmn") == NM_IAM_ERROR_INVALID_ARGUMENT); // username limit
    BOOST_TEST(nm_iam_set_user_fingerprint(&iam, "username", "foobar") == NM_IAM_ERROR_INVALID_ARGUMENT);
    BOOST_TEST(nm_iam_set_user_sct(&iam, "username", "abcdefghijklmn") == NM_IAM_ERROR_INVALID_ARGUMENT);
    BOOST_TEST(nm_iam_set_user_password(&iam, "username", "abcdefghijklmn") == NM_IAM_ERROR_INVALID_ARGUMENT);
    BOOST_TEST(nm_iam_set_user_display_name(&iam, "username", "abcdefghijklmn") == NM_IAM_ERROR_INVALID_ARGUMENT);
    BOOST_TEST(nm_iam_set_user_fcm_token(&iam, "username", "abcdefghijklmn") == NM_IAM_ERROR_INVALID_ARGUMENT);
    BOOST_TEST(nm_iam_set_user_fcm_project_id(&iam, "username", "abcdefghijklmn") == NM_IAM_ERROR_INVALID_ARGUMENT);

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}


BOOST_AUTO_TEST_CASE(load_partial_state, *boost::unit_test::timeout(180))
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
    BOOST_REQUIRE(nm_iam_set_notification_categories(&iam, &cats) == NM_IAM_ERROR_OK);
    nn_string_set_deinit(&cats);

    struct nm_iam_state* state = nm_iam_state_new();
    nm_iam_state_set_password_open_password(state, "password");
    BOOST_TEST(nm_iam_load_state(&iam, state));

    state = nm_iam_state_new();
    nm_iam_state_set_password_open_sct(state, "token");
    BOOST_TEST(nm_iam_load_state(&iam, state));

    state = nm_iam_state_new();
    nm_iam_state_set_password_open_pairing(state, true);
    BOOST_TEST(nm_iam_load_state(&iam, state));

    state = nm_iam_state_new();
    nm_iam_state_set_local_open_pairing(state, true);
    BOOST_TEST(nm_iam_load_state(&iam, state));

    state = nm_iam_state_new();
    nm_iam_state_set_password_invite_pairing(state, true);
    BOOST_TEST(nm_iam_load_state(&iam, state));

    state = nm_iam_state_new();
    nm_iam_state_set_local_initial_pairing(state, true);
    BOOST_TEST(nm_iam_load_state(&iam, state));

    state = nm_iam_state_new();
    nm_iam_state_set_open_pairing_role(state, "role1");
    BOOST_TEST(nm_iam_load_state(&iam, state));

    state = nm_iam_state_new();
    nm_iam_state_set_initial_pairing_username(state, "username");
    BOOST_TEST(nm_iam_load_state(&iam, state));

    state = nm_iam_state_new();
    nm_iam_state_set_friendly_name(state, "Friendly Name");
    BOOST_TEST(nm_iam_load_state(&iam, state));

    state = nm_iam_state_new();
    struct nm_iam_user* usr = nm_iam_state_user_new("username");
    nm_iam_state_user_set_fingerprint(usr, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    nm_iam_state_add_user(state, usr);
    BOOST_TEST(nm_iam_load_state(&iam, state));


    state = nm_iam_state_new();
    usr = nm_iam_state_user_new("username");
    nm_iam_state_user_set_sct(usr, "token2");
    nm_iam_state_add_user(state, usr);
    BOOST_TEST(nm_iam_load_state(&iam, state));


    state = nm_iam_state_new();
    usr = nm_iam_state_user_new("username");
    nm_iam_state_user_set_display_name(usr, "Display Name");
    nm_iam_state_add_user(state, usr);
    BOOST_TEST(nm_iam_load_state(&iam, state));


    state = nm_iam_state_new();
    usr = nm_iam_state_user_new("username");
    nm_iam_state_user_set_role(usr, "role1");
    nm_iam_state_add_user(state, usr);
    BOOST_TEST(nm_iam_load_state(&iam, state));


    state = nm_iam_state_new();
    usr = nm_iam_state_user_new("username");
    nm_iam_state_user_set_password(usr, "password2");
    nm_iam_state_add_user(state, usr);
    BOOST_TEST(nm_iam_load_state(&iam, state));


    state = nm_iam_state_new();
    usr = nm_iam_state_user_new("username");
    nm_iam_state_user_set_fcm_token(usr, "fcm_token");
    nm_iam_state_add_user(state, usr);
    BOOST_TEST(nm_iam_load_state(&iam, state));


    state = nm_iam_state_new();
    usr = nm_iam_state_user_new("username");
    nm_iam_state_user_set_fcm_project_id(usr, "fcm_project");
    nm_iam_state_add_user(state, usr);
    BOOST_TEST(nm_iam_load_state(&iam, state));


    state = nm_iam_state_new();
    usr = nm_iam_state_user_new("username");
    nn_string_set_init(&cats, np_allocator_get());
    nn_string_set_insert(&cats, "cat1");
    nn_string_set_insert(&cats, "cat2");
    nm_iam_state_user_set_notification_categories(usr, &cats);
    nn_string_set_deinit(&cats);
    nm_iam_state_add_user(state, usr);
    BOOST_TEST(nm_iam_load_state(&iam, state));

    nabto_device_stop(d);
    nm_iam_deinit(&iam);
    nabto_device_free(d);
}


BOOST_AUTO_TEST_SUITE_END()
