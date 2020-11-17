#include "nm_iam_internal.h"
#include "policies/nm_policy.h"
#include "nm_iam_user.h"
#include <nn/string_map.h>
#include <nn/llist.h>

static const char* LOGM = "iam";

bool nm_iam_internal_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct nn_string_map* attributesIn)
{
    NabtoDeviceError ec;
    char* fingerprint = NULL;
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
    if (nabto_device_connection_is_local(iam->device, ref)) {
        nn_string_map_insert(&attributes, "Connection:IsLocal", "true");
    } else {
        nn_string_map_insert(&attributes, "Connection:IsLocal", "false");
    }

    struct nm_iam_user* user = nm_iam_internal_find_user_by_fingerprint(iam, fingerprint);
    nabto_device_string_free(fingerprint);

    enum nm_iam_effect effect = NM_IAM_EFFECT_DENY;

    const char* roleStr = iam->conf->unpairedRole; // default if no user is found.

    if (user) {
        nn_string_map_insert(&attributes, "Connection:Username", user->username);
        roleStr = user->role;
    }
    struct nm_iam_role* role = nm_iam_internal_find_role(iam, roleStr);
    if (role == NULL) {
        effect = NM_IAM_EFFECT_ERROR;
    } else {
        effect = nm_iam_internal_check_access_role(iam, role, action, &attributes);
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

enum nm_iam_effect nm_iam_internal_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct nn_string_map* attributes)
{
    struct nm_policy_eval_state state;
    nm_policy_eval_init(&state);

    const char* policyStr;
    NN_STRING_SET_FOREACH(policyStr, &role->policies)
    {
        struct nm_iam_policy* policy = nm_iam_internal_find_policy(iam, policyStr);
        if (policy == NULL) {
             NN_LOG_ERROR(iam->logger, LOGM, "The policy %s for the role %s does not exist", policyStr, role->id);

            return NM_IAM_EFFECT_ERROR;
        }
        nm_policy_eval(&state, policy, action, attributes);
    }

    return nm_policy_eval_get_effect(&state);
}


struct nm_iam_user* nm_iam_internal_find_user_by_fingerprint(struct nm_iam* iam, const char* fingerprint)
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

struct nm_iam_user* nm_iam_internal_find_user_by_username(struct nm_iam* iam, const char* username)
{
    return nm_iam_state_find_user_by_username(iam->state, username);
}

struct nm_iam_role* nm_iam_internal_find_role(struct nm_iam* iam, const char* roleStr)
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

struct nm_iam_policy* nm_iam_internal_find_policy(struct nm_iam* iam, const char* policyStr)
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

struct nm_iam_user* nm_iam_internal_pair_new_client(struct nm_iam* iam, NabtoDeviceCoapRequest* request, const char* username)
{
    {
        struct nm_iam_user* user = nm_iam_internal_find_user_by_coap_request(iam, request);
        if (user != NULL) {
            // user is already paired.
            return user;
        }
    }

    if (username == NULL) {
        return NULL;
    }

    char* fingerprint = nm_iam_internal_get_fingerprint_from_coap_request(iam, request);
    if (fingerprint == NULL) {
        return NULL;
    }

    const char* role = iam->state->openPairingRole;

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
    nm_iam_user_set_sct(user, sct);

    nm_iam_internal_add_user(iam, user);

    nabto_device_string_free(fingerprint);
    nabto_device_string_free(sct);

    return user;
}

bool nm_iam_internal_add_user(struct nm_iam* iam, struct nm_iam_user* user)
{
    nn_llist_append(&iam->state->users, &user->listNode, user);

    if (user->sct != NULL) {
        nabto_device_add_server_connect_token(iam->device, user->sct);
    }

    nm_iam_internal_state_has_changed(iam);

    return true;
}

char* nm_iam_internal_get_fingerprint_from_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request)
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

struct nm_iam_user* nm_iam_internal_find_user_by_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request)
{
    char* fp = nm_iam_internal_get_fingerprint_from_coap_request(iam, request);
    if (fp == NULL) {
        return NULL;
    }
    struct nm_iam_user* user = nm_iam_internal_find_user_by_fingerprint(iam, fp);
    nabto_device_string_free(fp);
    return user;
}

struct nm_iam_user* nm_iam_internal_find_user(struct nm_iam* iam, const char* username)
{
    return nm_iam_internal_find_user_by_username(iam, username);
}

bool nm_iam_internal_get_users(struct nm_iam* iam, struct nn_string_set* usernames)
{
    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &iam->state->users)
    {
        nn_string_set_insert(usernames, user->username);
    }
    return true;
}

void nm_iam_internal_state_has_changed(struct nm_iam* iam)
{
    iam->stateHasChanged = true;
}

void nm_iam_internal_do_callbacks(struct nm_iam* iam)
{
    nm_iam_state_changed cb;
    void* userData;
    bool doit = false;
    {
        nm_iam_lock(iam);
        doit = iam->stateHasChanged;
        cb = iam->changeCallback.stateChanged;
        userData = iam->changeCallback.stateChangedData;
        iam->stateHasChanged = false;
        nm_iam_unlock(iam);
    }
    if (doit && cb != NULL) {
        cb(iam, userData);
    }
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
    return (validate_role_in_config(conf, conf->unpairedRole));
}

bool nm_iam_internal_load_configuration(struct nm_iam* iam, struct nm_iam_configuration* conf)
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

bool nm_iam_internal_load_state(struct nm_iam* iam, struct nm_iam_state* state)
{
    if (iam->state != NULL) {
        nm_iam_state_free(iam->state);
    }
    iam->state = state;

    nabto_device_add_server_connect_token(iam->device, iam->state->passwordOpenSct);
    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &iam->state->users) {
        nabto_device_add_server_connect_token(iam->device, user->sct);
    }

    return true;
}


void nm_iam_internal_init_coap_handlers(struct nm_iam* iam)
{
    nm_iam_pairing_get_init(&iam->coapPairingGetHandler, iam->device, iam);
    nm_iam_pairing_password_open_init(&iam->coapPairingPasswordOpenPostHandler, iam->device, iam);
    nm_iam_pairing_password_invite_init(&iam->coapPairingPasswordInvitePostHandler, iam->device, iam);
    nm_iam_pairing_local_open_init(&iam->coapPairingLocalOpenPostHandler, iam->device, iam);
    nm_iam_pairing_local_initial_init(&iam->coapPairingLocalInitialPostHandler, iam->device, iam);

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
    nm_iam_settings_get_init(&iam->coapIamSettingsGetHandler, iam->device, iam);
    nm_iam_settings_set_init(&iam->coapIamSettingsSetHandler, iam->device, iam);
}

void nm_iam_internal_deinit_coap_handlers(struct nm_iam* iam)
{
    nm_iam_coap_handler_deinit(&iam->coapPairingGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingPasswordOpenPostHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingPasswordInvitePostHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingLocalOpenPostHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingLocalInitialPostHandler);

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
    nm_iam_coap_handler_deinit(&iam->coapIamSettingsGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamSettingsSetHandler);
}

void nm_iam_internal_stop(struct nm_iam* iam)
{
    nm_iam_coap_handler_stop(&iam->coapPairingGetHandler);
    nm_iam_coap_handler_stop(&iam->coapPairingPasswordOpenPostHandler);
    nm_iam_coap_handler_stop(&iam->coapPairingPasswordInvitePostHandler);
    nm_iam_coap_handler_stop(&iam->coapPairingLocalOpenPostHandler);
    nm_iam_coap_handler_stop(&iam->coapPairingLocalInitialPostHandler);

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

    nm_iam_coap_handler_stop(&iam->coapIamSettingsGetHandler);
    nm_iam_coap_handler_stop(&iam->coapIamSettingsSetHandler);

    nm_iam_auth_handler_stop(&iam->authHandler);
    nm_iam_pake_handler_stop(&iam->pakeHandler);
}

enum nm_iam_error nm_iam_internal_create_user(struct nm_iam* iam, const char* username)
{

    struct nm_iam_user* user;
    user = nm_iam_internal_find_user_by_username(iam, username);
    if (user != NULL) {
        return NM_IAM_ERROR_USER_EXISTS;
    }

    user = nm_iam_user_new(username);
    if (user == NULL) {
        return NM_IAM_ERROR_INTERNAL;
    }
    char* sct;
    if (nabto_device_create_server_connect_token(iam->device, &sct) != NABTO_DEVICE_EC_OK ||
        !nm_iam_user_set_sct(user, sct))
    {
        nabto_device_string_free(sct);
        nm_iam_user_free(user);
        return NM_IAM_ERROR_INTERNAL;
    }
    nabto_device_string_free(sct);

    nm_iam_internal_add_user(iam, user);
    return NM_IAM_ERROR_OK;
}

enum nm_iam_error nm_iam_internal_set_user_fingerprint(struct nm_iam* iam, const char* username, const char* fingerprint)
{
    struct nm_iam_user* user = nm_iam_internal_find_user_by_username(iam, username);
    if (user == NULL) {
        return NM_IAM_ERROR_NO_SUCH_USER;
    }

    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    // todo handle invalid fingerprint format.
    if (nm_iam_user_set_fingerprint(user, fingerprint)) {
        ec = NM_IAM_ERROR_OK;
    }
    nm_iam_internal_state_has_changed(iam);
    return ec;
}

enum nm_iam_error nm_iam_internal_set_user_sct(struct nm_iam* iam, const char* username, const char* sct)
{
    struct nm_iam_user* user = nm_iam_internal_find_user_by_username(iam, username);
    if (user == NULL) {
        return NM_IAM_ERROR_NO_SUCH_USER;
    }

    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    if (nm_iam_user_set_sct(user, sct)) {
        ec = NM_IAM_ERROR_OK;
    }
    nm_iam_internal_state_has_changed(iam);
    return ec;
}

enum nm_iam_error nm_iam_internal_set_user_password(struct nm_iam* iam, const char* username, const char* password)
{
    struct nm_iam_user* user = nm_iam_internal_find_user_by_username(iam, username);
    if (user == NULL) {
        return NM_IAM_ERROR_NO_SUCH_USER;
    }

    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    if (nm_iam_user_set_password(user, password)) {
        ec = NM_IAM_ERROR_OK;
    }
    nm_iam_internal_state_has_changed(iam);
    return ec;
}

enum nm_iam_error nm_iam_internal_set_user_role(struct nm_iam* iam, const char* username, const char* roleStr)
{
    struct nm_iam_user* user = nm_iam_internal_find_user_by_username(iam, username);
    if (user == NULL) {
        return NM_IAM_ERROR_NO_SUCH_USER;
    }

    struct nm_iam_role* role = nm_iam_internal_find_role(iam, roleStr);
    if (role == NULL) {
        return NM_IAM_ERROR_NO_SUCH_ROLE;
    }

    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    if (nm_iam_user_set_role(user, roleStr)) {
        ec = NM_IAM_ERROR_OK;
    }
    nm_iam_internal_state_has_changed(iam);
    return ec;
}

enum nm_iam_error nm_iam_internal_set_user_display_name(struct nm_iam* iam, const char* username, const char* displayName)
{
    struct nm_iam_user* user = nm_iam_internal_find_user_by_username(iam, username);
    if (user == NULL) {
        return NM_IAM_ERROR_NO_SUCH_USER;
    }

    enum nm_iam_error ec = NM_IAM_ERROR_INTERNAL;
    if (nm_iam_user_set_display_name(user, displayName)) {
        ec = NM_IAM_ERROR_OK;
    }
    nm_iam_internal_state_has_changed(iam);
    return ec;
}

enum nm_iam_error nm_iam_internal_delete_user(struct nm_iam* iam, const char* username)
{
    struct nm_iam_user* user = nm_iam_internal_find_user_by_username(iam, username);
    if (user == NULL) {
        return NM_IAM_ERROR_NO_SUCH_USER;
    }

    nn_llist_erase_node(&user->listNode);
    nm_iam_user_free(user);

    nm_iam_internal_state_has_changed(iam);
    return NM_IAM_ERROR_OK;
}
