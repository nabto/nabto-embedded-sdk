#include "nm_iam.h"
#include "nm_iam_internal.h"
#include "nm_iam_user.h"
#include "nm_iam_role.h"
#include "policies/nm_policy.h"

#include <nabto/nabto_device_experimental.h>

#include <nn/log.h>

#include <stdlib.h>
#include <time.h>

static const char* LOGM = "iam";

static enum nm_iam_effect nm_iam_check_access_user(struct nm_iam* iam, struct nm_iam_user* user, const char* action, const struct nn_string_map* attributes);
static enum nm_iam_effect nm_iam_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct nn_string_map* attributes);

static void init_coap_handlers(struct nm_iam* iam);
static void deinit_coap_handlers(struct nm_iam* iam);

static char* get_fingerprint_from_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request);



void nm_iam_init(struct nm_iam* iam, NabtoDevice* device, struct nn_log* logger)
{
    memset(iam, 0, sizeof(struct nm_iam));
    srand(time(0));
    iam->device = device;
    iam->logger = logger;

    nm_iam_auth_handler_init(&iam->authHandler, iam->device, iam);
    nm_iam_pake_handler_init(&iam->pakeHandler, iam->device, iam);

    init_coap_handlers(iam);
}

bool validate_role_in_config(struct nm_iam_configuration* conf, const char* roleStr)
{
     if (roleStr == NULL) {
        return true;
    }
    struct nm_iam_role* role;
    NN_LLIST_FOREACH(role, &conf->roles)
    {
        if (strcmp(role->id, roleStr) == 0) {
            return true;
        }
    }
    return false;
}

bool validate_configuration(struct nm_iam_configuration* conf) {
    return (validate_role_in_config(conf, conf->firstUserRole) &&
            validate_role_in_config(conf, conf->secondaryUserRole) &&
            validate_role_in_config(conf, conf->unpairedRole));
}

bool nm_iam_load_configuration(struct nm_iam* iam, struct nm_iam_configuration* conf)
{
    if (!validate_configuration(conf)) {
        return false;
    }
    if (iam->conf != NULL) {
        nm_iam_configuration_free(iam->conf);
    }
    iam->conf = conf;
    return true;
}

bool nm_iam_load_state(struct nm_iam* iam, struct nm_iam_state* state)
{
    if (iam->state != NULL) {
        nm_iam_state_free(iam->state);
    }
    iam->state = state;

    nabto_device_add_server_connect_token(iam->device, iam->state->globalSct);
    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &iam->state->users) {
        nabto_device_add_server_connect_token(iam->device, user->serverConnectToken);
    }

    return true;
}

void nm_iam_stop(struct nm_iam* iam)
{
    nm_iam_coap_handler_stop(&iam->coapPairingGetHandler);
    nm_iam_coap_handler_stop(&iam->coapPairingPasswordOpenPostHandler);
    nm_iam_coap_handler_stop(&iam->coapPairingPasswordInvitePostHandler);
    nm_iam_coap_handler_stop(&iam->coapPairingLocalOpenPostHandler);

    nm_iam_coap_handler_stop(&iam->coapIamMeGetHandler);
    nm_iam_coap_handler_stop(&iam->coapIamUsersGetHandler);
    nm_iam_coap_handler_stop(&iam->coapIamUsersUserGetHandler);
    nm_iam_coap_handler_stop(&iam->coapIamUsersUserCreateHandler);

    nm_iam_coap_handler_stop(&iam->coapIamUsersUserDeleteHandler);
    nm_iam_coap_handler_stop(&iam->coapIamRolesGetHandler);
    nm_iam_coap_handler_stop(&iam->coapIamUsersUserSetRoleHandler);
    nm_iam_coap_handler_stop(&iam->coapIamUsersUserSetUsernameHandler);
    nm_iam_coap_handler_stop(&iam->coapIamUsersUserSetDisplayNameHandler);
    nm_iam_coap_handler_stop(&iam->coapIamUsersUserSetFingerprintHandler);
    nm_iam_coap_handler_stop(&iam->coapIamUsersUserSetSctHandler);
    nm_iam_coap_handler_stop(&iam->coapIamUsersUserSetPasswordHandler);

    nm_iam_auth_handler_stop(&iam->authHandler);
    nm_iam_pake_handler_stop(&iam->pakeHandler);
}

void nm_iam_deinit(struct nm_iam* iam)
{
    deinit_coap_handlers(iam);

    nm_iam_auth_handler_deinit(&iam->authHandler);
    nm_iam_pake_handler_deinit(&iam->pakeHandler);

    nm_iam_state_free(iam->state);
    nm_iam_configuration_free(iam->conf);
}

bool nm_iam_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct nn_string_map* attributesIn)
{
    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint(iam->device, ref, &fingerprint);
    if (ec) {
        return false;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes);


    if (attributesIn) {
        struct nn_string_map_iterator it;
        for (it = nn_string_map_begin(attributesIn); !nn_string_map_is_end(&it); nn_string_map_next(&it))
        {
            nn_string_map_insert(&attributes, nn_string_map_key(&it), nn_string_map_value(&it));
        }
    }

    struct nm_iam_user* user = nm_iam_find_user_by_fingerprint(iam, fingerprint);
    nabto_device_string_free(fingerprint);

    enum nm_iam_effect effect = NM_IAM_EFFECT_DENY;

    if (!user && nabto_device_connection_is_password_authenticated(iam->device, ref)) {
        const char* username = nabto_device_connection_get_password_authentication_username(iam->device, ref);
        if (username != NULL) {
            // authenticated with non-empty username
            user = nm_iam_find_user(iam, username);
        }
    }
    if (user) {
        nn_string_map_insert(&attributes, "Connection:Username", user->username);
        if (nabto_device_connection_is_local(iam->device, ref)) {
            nn_string_map_insert(&attributes, "Connection:IsLocal", "true");
        } else {
            nn_string_map_insert(&attributes, "Connection:IsLocal", "false");
        }
        effect = nm_iam_check_access_user(iam, user, action, &attributes);
    } else {
        struct nm_iam_role* role = nm_iam_find_role(iam, iam->conf->unpairedRole);
        if (role == NULL) {
            effect = NM_IAM_EFFECT_ERROR;
        } else {
            effect = nm_iam_check_access_role(iam, role, action, &attributes);
        }
    }

    nn_string_map_deinit(&attributes);


    bool verdict = false;
    if (effect == NM_IAM_EFFECT_ALLOW) {
        verdict = true;
    }

    const char* username;
    if (user) {
        username = user->username;
    } else {
        username = "Not Paired";
    }

    NN_LOG_INFO(iam->logger, LOGM, "IAM access from the user: %s, request action: %s, verdict: %s", username, action, verdict?"ALLOW":"DENY");

    return verdict;
}


enum nm_iam_effect nm_iam_check_access_user(struct nm_iam* iam, struct nm_iam_user* user, const char* action, const struct nn_string_map* attributes)
{
    struct nm_iam_role* role = nm_iam_find_role(iam, user->role);
    if (role == NULL) {
        return NM_IAM_EFFECT_NO_MATCH;
    }
    return nm_iam_check_access_role(iam, role, action, attributes);
}

enum nm_iam_effect nm_iam_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct nn_string_map* attributes)
{
    struct nm_policy_eval_state state;
    nm_policy_eval_init(&state);

    const char* policyStr;
    NN_STRING_SET_FOREACH(policyStr, &role->policies)
    {
        struct nm_iam_policy* policy = nm_iam_find_policy(iam, policyStr);
        if (policy == NULL) {
             NN_LOG_ERROR(iam->logger, LOGM, "The policy %s for the role %s does not exists", policyStr, role->id);

            return NM_IAM_EFFECT_ERROR;
        }
        nm_policy_eval(&state, policy, action, attributes);
    }

    return nm_policy_eval_get_effect(&state);
}

void init_coap_handlers(struct nm_iam* iam)
{

    nm_iam_pairing_get_init(&iam->coapPairingGetHandler, iam->device, iam);
    nm_iam_pairing_password_open_init(&iam->coapPairingPasswordOpenPostHandler, iam->device, iam);
    nm_iam_pairing_password_invite_init(&iam->coapPairingPasswordInvitePostHandler, iam->device, iam);
    nm_iam_pairing_local_open_init(&iam->coapPairingLocalOpenPostHandler, iam->device, iam);

    nm_iam_get_me_init(&iam->coapIamMeGetHandler, iam->device, iam);
    nm_iam_list_users_init(&iam->coapIamUsersGetHandler, iam->device, iam);
    nm_iam_get_user_init(&iam->coapIamUsersUserGetHandler, iam->device, iam);
    nm_iam_create_user_init(&iam->coapIamUsersUserCreateHandler, iam->device, iam);
    nm_iam_delete_user_init(&iam->coapIamUsersUserDeleteHandler, iam->device, iam);
    nm_iam_list_roles_init(&iam->coapIamRolesGetHandler, iam->device, iam);
    nm_iam_set_user_role_init(&iam->coapIamUsersUserSetRoleHandler, iam->device, iam);
    nm_iam_set_user_username_init(&iam->coapIamUsersUserSetUsernameHandler, iam->device, iam);
    nm_iam_set_user_display_name_init(&iam->coapIamUsersUserSetDisplayNameHandler, iam->device, iam);
    nm_iam_set_user_fingerprint_init(&iam->coapIamUsersUserSetFingerprintHandler, iam->device, iam);
    nm_iam_set_user_sct_init(&iam->coapIamUsersUserSetSctHandler, iam->device, iam);
    nm_iam_set_user_password_init(&iam->coapIamUsersUserSetPasswordHandler, iam->device, iam);
}

void deinit_coap_handlers(struct nm_iam* iam)
{
    nm_iam_coap_handler_deinit(&iam->coapPairingGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingPasswordOpenPostHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingPasswordInvitePostHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingLocalOpenPostHandler);

    nm_iam_coap_handler_deinit(&iam->coapIamMeGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserCreateHandler);

    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserDeleteHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamRolesGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserSetRoleHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserSetUsernameHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserSetDisplayNameHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserSetFingerprintHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserSetSctHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserSetPasswordHandler);
}



struct nm_iam_user* nm_iam_find_user_by_fingerprint(struct nm_iam* iam, const char* fingerprint)
{
    if (fingerprint == NULL) {
        return NULL;
    }
    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &iam->state->users) {
        if (user->fingerprint != NULL && strcmp(user->fingerprint, fingerprint) == 0) {
            return user;
        }
    }
    return NULL;
}

struct nm_iam_user* nm_iam_find_user_by_username(struct nm_iam* iam, const char* username)
{
    if (username == NULL) {
        return NULL;
    }
    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &iam->state->users) {
        if (user->username != NULL && strcmp(user->username, username) == 0) {
            return user;
        }
    }
    return NULL;
}

struct nm_iam_role* nm_iam_find_role(struct nm_iam* iam, const char* roleStr)
{
    if (roleStr == NULL) {
        return NULL;
    }
    struct nm_iam_role* role;
    NN_LLIST_FOREACH(role, &iam->conf->roles)
    {
        if (strcmp(role->id, roleStr) == 0) {
            return role;
        }
    }
    return NULL;
}

struct nm_iam_policy* nm_iam_find_policy(struct nm_iam* iam, const char* policyStr)
{
    if (policyStr == NULL) {
        return NULL;
    }
    struct nm_iam_policy* policy;
    NN_LLIST_FOREACH(policy, &iam->conf->policies)
    {
        if (strcmp(policy->id, policyStr) == 0) {
            return policy;
        }
    }
    return NULL;
}

struct nm_iam_user* nm_iam_pair_new_client(struct nm_iam* iam, NabtoDeviceCoapRequest* request, const char* username)
{
    {
        struct nm_iam_user* user = nm_iam_find_user_by_coap_request(iam, request);
        if (user != NULL) {
            // user is already paired.
            return user;
        }
    }

    if (username == NULL) {
        return NULL;
    }

    char* fingerprint = get_fingerprint_from_coap_request(iam, request);
    if (fingerprint == NULL) {
        return NULL;
    }

    bool firstUser = nn_llist_empty(&iam->state->users);

    const char* role = NULL;
    if (firstUser) {
        role = iam->conf->firstUserRole;
    } else {
        role = iam->conf->secondaryUserRole;
    }

    if (role == NULL) {
        return NULL;
    }

    char* sct;
    NabtoDeviceError ec = nabto_device_create_server_connect_token(iam->device, &sct);
    if (ec != NABTO_DEVICE_EC_OK) {
        return NULL;
    }

    struct nm_iam_user* user = nm_iam_user_new(username);

    nm_iam_user_set_role(user, role);

    nm_iam_user_set_fingerprint(user, fingerprint);
    nm_iam_user_set_server_connect_token(user, sct);

    nm_iam_add_user(iam, user);

    nabto_device_string_free(fingerprint);
    nabto_device_string_free(sct);

    return user;
}

bool nm_iam_add_user(struct nm_iam* iam, struct nm_iam_user* user)
{
    nn_llist_append(&iam->state->users, &user->listNode, user);

    if (user->serverConnectToken != NULL) {
        nabto_device_add_server_connect_token(iam->device, user->serverConnectToken);
    }

    if (iam->changeCallback.userChanged) {
        iam->changeCallback.userChanged(iam, user->username, iam->changeCallback.userChangedData);
    }
    return true;
}

char* get_fingerprint_from_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request)
{
    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);

    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint(iam->device, ref, &fingerprint);
    if (ec != NABTO_DEVICE_EC_OK) {
        return NULL;
    }
    return fingerprint;
}

struct nm_iam_user* nm_iam_find_user_by_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request)
{
    char* fp = get_fingerprint_from_coap_request(iam, request);
    if (fp == NULL) {
        return NULL;
    }
    struct nm_iam_user* user = nm_iam_find_user_by_fingerprint(iam, fp);
    nabto_device_string_free(fp);
    return user;
}

struct nm_iam_user* nm_iam_find_user(struct nm_iam* iam, const char* username)
{
    return nm_iam_find_user_by_username(iam, username);
}

void nm_iam_set_user_changed_callback(struct nm_iam* iam, nm_iam_user_changed userChanged, void* data)
{
    iam->changeCallback.userChanged = userChanged;
    iam->changeCallback.userChangedData = data;
}

bool nm_iam_get_users(struct nm_iam* iam, struct nn_string_set* usernames)
{
    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &iam->state->users)
    {
        nn_string_set_insert(usernames, user->username);
    }
    return true;
}

void nm_iam_delete_user(struct nm_iam* iam, const char* username)
{
    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &iam->state->users) {
        if (strcmp(user->username, username) == 0) {
            nn_llist_erase_node(&user->listNode);
            nm_iam_user_free(user);

            nm_iam_user_has_changed(iam, username);
            return;
        }

    }
}

void nm_iam_user_has_changed(struct nm_iam* iam, const char* username) 
{
    if (iam->changeCallback.userChanged) {
        iam->changeCallback.userChanged(iam, username, iam->changeCallback.userChangedData);
    }
}

bool nm_iam_set_user_role(struct nm_iam* iam, const char* username, const char* roleId)
{
    struct nm_iam_user* user = nm_iam_find_user(iam, username);
    struct nm_iam_role* role = nm_iam_find_role(iam, roleId);

    if (user == NULL) {
        NN_LOG_INFO(iam->logger, LOGM, "The username %s does not exists", username);
        return false;
    }
    if (role == NULL) {
        NN_LOG_INFO(iam->logger, LOGM, "The role %s does not exists", roleId);
        return false;
    }

    bool status = nm_iam_user_set_role(user, roleId);

    if (status == true) {
        if (iam->changeCallback.userChanged) {
            iam->changeCallback.userChanged(iam, username, iam->changeCallback.userChangedData);
        }
    }
    return status;
}
