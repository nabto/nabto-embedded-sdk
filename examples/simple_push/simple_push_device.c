#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>
#include <modules/fs/posix/nm_fs_posix.h>
#include <apps/common/string_file.h>

#include <cjson/cJSON.h>

#ifdef _WIN32
#include <Windows.h>
#define NEWLINE "\r\n"
#else
#include <unistd.h>
#define NEWLINE "\n"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <signal.h>

const char* keyFile = "device.key";
const char* stateFile = "simple_push_state.json";

static struct nn_allocator defaultAllocator = {
  .calloc = calloc,
  .free = free
};

enum nn_log_severity logLevel = NN_LOG_SEVERITY_TRACE;

void send_notification_to_category(NabtoDevice* device, struct nm_iam* iam, const char* category);
void read_push_trigger(NabtoDevice* device, struct nm_iam* iam);
bool build_fcm_for_user(NabtoDevice* device, NabtoDeviceFcmNotification* fcm, struct nm_iam_user* user, const char* title, const char* body);
bool start_device(NabtoDevice* device, const char* productId, const char* deviceId, struct nm_iam* iam);
bool setup_iam(NabtoDevice* device, struct nm_iam* iam);
void handle_device_error(NabtoDevice* d, char* msg);
void iam_logger(void* data, enum nn_log_severity severity, const char* module,
                const char* file, int line,
                const char* fmt, va_list args);
bool generate_default_state(NabtoDevice* device);

NabtoDevice* device_;
struct nn_log* iamLogger_ = NULL;

int main(int argc, char* argv[]) {

    if (argc != 3) {
        printf("The example takes exactly two arguments. %s <product-id> <device-id>" NEWLINE, argv[0]);
        return -1;
    }

    char* productId = argv[1];
    char* deviceId = argv[2];

    struct nm_iam iam;

    printf("Nabto Embedded SDK Version %s\n", nabto_device_version());

    if ((device_ = nabto_device_new()) == NULL) {
        handle_device_error(NULL, "Failed to allocate device");
        return -1;
    }

    if (!start_device(device_, productId, deviceId, &iam)) {
        handle_device_error(device_, "Failed to start device");
        return -1;
    }

    read_push_trigger(device_, &iam);

    nabto_device_stop(device_);
    nm_iam_deinit(&iam);
    nabto_device_free(device_);
    if (iamLogger_) {
        free(iamLogger_);
        iamLogger_ = NULL;
    }

    printf("Device cleaned up and closing\n");
}

void read_push_trigger(NabtoDevice* device, struct nm_iam* iam)
{
    char cat = 0;
    while(true) {
        if (cat != '\n') {
            printf("Pick a category to trigger a push notification for\n");
            printf("[i] info category\n");
            printf("[w] warn category\n");
            printf("[a] alert category\n");
            printf("[q] Close the device and quit\n");
        }
        (void)scanf("%c", &cat);
        if (cat == 'i') {
            send_notification_to_category(device, iam, "Info");
        } else if (cat == 'w') {
            send_notification_to_category(device, iam, "Warn");
        } else if (cat == 'a') {
            send_notification_to_category(device, iam, "Alert");
        } else if (cat == 'q') {
            return;
        } else if (cat != '\n') {
            printf("Invalid input: %c please pick a valid option [i,w,a,q] \n", cat);
        }
    }
}

void send_notification_to_category(NabtoDevice* device, struct nm_iam* iam, const char* category)
{
    printf("Sending FCM notification to all users subsribed to category %s\n", category);
    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    struct nm_iam_state* state = nm_iam_dump_state(iam);
    NabtoDeviceError ec;
    void* u;
    NN_LLIST_FOREACH(u, &state->users) {
        struct nm_iam_user* user = (struct nm_iam_user*)u;
        if (nn_string_set_contains(&user->notificationCategories, category)) {
            // Found user with category
            NabtoDeviceFcmNotification* fcm = nabto_device_fcm_notification_new(device);
            if (build_fcm_for_user(device, fcm, user, category, "Act now")) {
                nabto_device_fcm_send(fcm, fut);
                nabto_device_future_wait(fut);
                if ((ec = nabto_device_future_error_code(fut)) != NABTO_DEVICE_EC_OK) {
                    printf("Failed to send Push notification to Basestation: %s\n", nabto_device_error_get_string(ec));
                } else {
                    printf("Push notification successfully sent to Basestation. FCM returned status %u: %s\n", nabto_device_fcm_notification_get_response_status_code(fcm), nabto_device_fcm_notification_get_response_body(fcm));
                }
            }
            nabto_device_fcm_notification_free(fcm);
        }
    }
    nm_iam_state_free(state);
    nabto_device_future_free(fut);
    printf("Sent all notifications for category %s\n", category);
}

bool build_fcm_for_user(NabtoDevice* device, NabtoDeviceFcmNotification* fcm, struct nm_iam_user* user, const char* title, const char* body)
{
    (void)device;
    cJSON* root = cJSON_CreateObject();
    cJSON* message = cJSON_CreateObject();
    cJSON* notification = cJSON_CreateObject();
    cJSON_AddItemToObject(notification, "title", cJSON_CreateString(title));
    cJSON_AddItemToObject(notification, "body", cJSON_CreateString(body));
    cJSON_AddItemToObject(message, "notification", notification);
    cJSON_AddItemToObject(message, "token", cJSON_CreateString(user->fcmToken));
    cJSON_AddItemToObject(root, "message", message);
    char* payload = cJSON_PrintUnformatted(root);
    if (nabto_device_fcm_notification_set_payload(fcm, payload) != NABTO_DEVICE_EC_OK ||
        nabto_device_fcm_notification_set_project_id(fcm, user->fcmProjectId) != NABTO_DEVICE_EC_OK)
    {
        printf("Failed to set payload or project ID for FCM notification\n");
        printf("payload: %s\n", payload);
        printf("project: %s\n", user->fcmProjectId);
        free(payload);
        cJSON_Delete(root);
        return false;
    }
    free(payload);
    cJSON_Delete(root);
    return true;
}

bool start_device(NabtoDevice* device, const char* productId, const char* deviceId, struct nm_iam* iam)
{
    NabtoDeviceError ec;
    char* privateKey;
    char* fp;

    struct nm_fs fsImpl = nm_fs_posix_get_impl();

    if (!string_file_exists(&fsImpl, keyFile)) {
        if ((ec = nabto_device_create_private_key(device, &privateKey)) != NABTO_DEVICE_EC_OK) {
            printf("Failed to create private key, ec=%s\n", nabto_device_error_get_message(ec));
            return false;
        }
        if (!string_file_save(&fsImpl, keyFile, privateKey)) {
            printf("Failed to persist private key to file: %s\n", keyFile);
            nabto_device_string_free(privateKey);
            return false;
        }
        nabto_device_string_free(privateKey);
    }

    if (!string_file_load(&fsImpl, keyFile, &privateKey)) {
        printf("Failed to load private key from file: %s\n", keyFile);
        return false;
    }

    if ((ec = nabto_device_set_private_key(device, privateKey)) != NABTO_DEVICE_EC_OK) {
        printf("Failed to set private key, ec=%s\n", nabto_device_error_get_message(ec));
        free(privateKey);
        return false;
    }
    free(privateKey);

    if (nabto_device_get_device_fingerprint(device, &fp) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    printf("Device: %s.%s with fingerprint: [%s]\n", productId, deviceId, fp);
    nabto_device_string_free(fp);

    if (nabto_device_set_product_id(device, productId) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_device_id(device, deviceId) != NABTO_DEVICE_EC_OK ||
        nabto_device_enable_mdns(device) != NABTO_DEVICE_EC_OK ||
        nabto_device_mdns_add_subtype(device, "simplepush") != NABTO_DEVICE_EC_OK)
    {
        return false;
    }

    const char* server = getenv("NABTO_SERVER");
    if (server) {
        if (nabto_device_set_server_url(device, server) != NABTO_DEVICE_EC_OK) {
            return false;
        }
    }


    char* envLogLevel = getenv("NABTO_LOG_LEVEL");
    if (envLogLevel) {
        if (strcmp(envLogLevel, "trace") == 0) {
            logLevel = NN_LOG_SEVERITY_TRACE;
        } else if (strcmp(envLogLevel, "info") == 0) {
            logLevel = NN_LOG_SEVERITY_INFO;
        } else if (strcmp(envLogLevel, "warn") == 0) {
            logLevel = NN_LOG_SEVERITY_WARN;
        } else if (strcmp(envLogLevel, "ERROR") == 0) {
            logLevel = NN_LOG_SEVERITY_ERROR;
        } else {
            printf("Invalid loglevel %s provided\n", envLogLevel);
            return false;
        }
        if (nabto_device_set_log_level(device, envLogLevel) ||
            nabto_device_set_log_std_out_callback(device) != NABTO_DEVICE_EC_OK)
        {
            printf("Failed to configure logging\n");
            return false;
        }
    }

    if (!setup_iam(device, iam)) {
        printf("Failed to setup the IAM module\n");
        return false;
    }

    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_start(device, fut);

    ec = nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }

    return true;
}

void iam_user_changed(struct nm_iam* iam, void* userData)
{
    (void)userData;
    struct nm_iam_state* state = nm_iam_dump_state(iam);
    char* stateStr;

    struct nm_fs fsImpl = nm_fs_posix_get_impl();

    nm_iam_serializer_state_dump_json(state, &stateStr);
    if (!string_file_save(&fsImpl, stateFile, stateStr)) {
        printf("Failed to persist changed IAM state to file: %s\n", stateFile);
    }
    nm_iam_serializer_string_free(stateStr);
    nm_iam_state_free(state);
}

/**
 * Function setting up configuration and state for the IAM module
 */
bool setup_iam(NabtoDevice* device, struct nm_iam* iam)
{

    struct nm_fs fsImpl = nm_fs_posix_get_impl();

    iamLogger_ = (struct nn_log*)calloc(1, sizeof(struct nn_log));
    if (iamLogger_ == NULL) {
        return false;
    }
    iamLogger_->logPrint = &iam_logger;
    nm_iam_init(iam, device, iamLogger_);

    struct nn_string_set cats;
    nn_string_set_init(&cats, &defaultAllocator);
    nn_string_set_insert(&cats, "Info");
    nn_string_set_insert(&cats, "Warn");
    nn_string_set_insert(&cats, "Alert");
    if(nm_iam_set_notification_categories(iam, &cats) != NM_IAM_ERROR_OK) { return false; }
    nn_string_set_deinit(&cats);

    struct nm_iam_configuration* iamConfig = nm_iam_configuration_new();
    if (iamConfig == NULL) { return false; }

    /**** POLICY CONF ****/
    struct nm_iam_policy* policy;
    struct nm_iam_statement* stmt;
    {
        policy = nm_iam_configuration_policy_new("Unpaired");
        if (policy == NULL) { return false; }
        stmt = nm_iam_configuration_policy_create_statement(policy, NM_IAM_EFFECT_ALLOW);
        if (stmt == NULL ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:GetPairing") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:PairingPasswordOpen") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:PairingPasswordInvite") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:PairingLocalOpen") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:PairingLocalInitial") ||
            !nm_iam_configuration_add_policy(iamConfig, policy))
        { return false; }
    }

    {
        policy = nm_iam_configuration_policy_new("Paired");
        if (policy == NULL) { return false; }
        stmt = nm_iam_configuration_policy_create_statement(policy, NM_IAM_EFFECT_ALLOW);
        if (stmt == NULL ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:GetPairing") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:ListUsers") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:ListNotificationCategories") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:GetUser") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:DeleteUser") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserRole") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserUsername") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserDisplayName") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserFingerprint") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserSct") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserPassword") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserNotificationCategories") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserFcm") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:CreateUser") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:ListRoles") ||
            !nm_iam_configuration_statement_add_action(stmt, "IAM:SendUserFcmTest") ||
            !nm_iam_configuration_add_policy(iamConfig, policy))
        { return false; }
    }

    /**** ROLE CONF ****/
    struct nm_iam_role* r;
    {
        r = nm_iam_configuration_role_new("Unpaired");
        if ( r == NULL ||
             !nm_iam_configuration_role_add_policy(r, "Unpaired") ||
             !nm_iam_configuration_add_role(iamConfig, r))
        { return false; }
    }

    {
        r = nm_iam_configuration_role_new("Paired");
        if ( r == NULL ||
             !nm_iam_configuration_role_add_policy(r, "Paired") ||
             !nm_iam_configuration_add_role(iamConfig, r))
        { return false; }
    }
    if (!nm_iam_configuration_set_unpaired_role(iamConfig, "Unpaired")) { return false; }

    /**** STATE CONF ****/

    if (!string_file_exists(&fsImpl, stateFile)) {
        if (!generate_default_state(device)) {
            return false;
        }
    }

    char* stateStr;
    if (!string_file_load(&fsImpl, stateFile, &stateStr)) {
        printf("Failed to load IAM state from file: %s\n", stateFile);
        return false;
    }

    struct nm_iam_state* state = nm_iam_state_new();
    if (state == NULL) { return false; }
    if (!nm_iam_serializer_state_load_json(state, stateStr, iamLogger_)) {
        printf("Failed to deserialize IAM state from string: %s\n", stateStr);
        free(stateStr);
        return false;
    }
    free(stateStr);

    if (!nm_iam_load_configuration(iam, iamConfig) ||
        !nm_iam_load_state(iam, state)) {
        return false;
    }
    nm_iam_set_state_changed_callback(iam, iam_user_changed, NULL);
    return true;
}

void handle_device_error(NabtoDevice* d, char* msg)
{
    NabtoDeviceFuture* f = nabto_device_future_new(d);
    if (d) {
        nabto_device_close(d, f);
        nabto_device_future_wait(f);
        nabto_device_stop(d);
        nabto_device_free(d);
    }
    if (f) {
        nabto_device_future_free(f);
    }
    if (iamLogger_) {
        free(iamLogger_);
        iamLogger_ = NULL;
    }
    printf("%s", msg);
}

void iam_logger(void* data, enum nn_log_severity severity, const char* module,
                const char* file, int line,
                const char* fmt, va_list args)
{
    (void)data; (void)module;
    if (logLevel > 0 && severity <= logLevel) {
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

bool generate_default_state(NabtoDevice* device)
{
    struct nm_fs fsImpl = nm_fs_posix_get_impl();

    struct nm_iam_state* state = nm_iam_state_new();
    if (state == NULL) { return false; }

    char* sct = NULL;
    if (nabto_device_create_server_connect_token(device, &sct) != NABTO_DEVICE_EC_OK ||
        !nm_iam_state_set_password_open_sct(state, sct) )
    { return false; }
    nabto_device_string_free(sct);

    nm_iam_state_set_password_open_pairing(state, true);
    nm_iam_state_set_local_open_pairing(state, true);
    nm_iam_state_set_password_invite_pairing(state, true);
    nm_iam_state_set_local_initial_pairing(state, true);

    if (!nm_iam_state_set_password_open_password(state, "openPassword") ||
        !nm_iam_state_set_open_pairing_role(state, "Paired") ||
        !nm_iam_state_set_initial_pairing_username(state, "initial"))
    { return false; }

    struct nm_iam_user* user = nm_iam_state_user_new("initial");
    if (user == NULL ||
        !nm_iam_state_user_set_display_name(user, "Initial Name") ||
        !nm_iam_state_user_set_role(user, "Paired") ||
        !nm_iam_state_user_set_password(user, "initialPassword"))
    { return false; }

    sct = NULL;
    if (nabto_device_create_server_connect_token(device, &sct) != NABTO_DEVICE_EC_OK ||
        !nm_iam_state_user_set_sct(user, sct) ||
        !nm_iam_state_add_user(state, user) )
    { return false; }
    nabto_device_string_free(sct);

    char* stateStr;
    nm_iam_serializer_state_dump_json(state, &stateStr);
    nm_iam_state_free(state);
    if (!string_file_save(&fsImpl, stateFile, stateStr)) {
        printf("Failed to persist default IAM state to file: %s\n", stateFile);
        nm_iam_serializer_string_free(stateStr);
        return false;
    } else {
        nm_iam_serializer_string_free(stateStr);
        return true;
    }
}
