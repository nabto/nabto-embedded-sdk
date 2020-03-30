#include "nm_iam.h"
#include "nm_iam_internal.h"
#include "nm_iam_user.h"
#include "nm_iam_role.h"

#include "nm_iam_coap_handler.h"

#include <modules/policies/nm_effect.h>
#include <modules/policies/nm_policy.h>

#include <nn/log.h>

#include <stdlib.h>

static const char* LOGM = "iam";

static enum nm_effect nm_iam_check_access_user(struct nm_iam* iam, struct nm_iam_user* user, const char* action, const struct nn_string_map* attributes);
static enum nm_effect nm_iam_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct nn_string_map* attributes);

static void init_coap_handlers(struct nm_iam* iam);
static void deinit_coap_handlers(struct nm_iam* iam);

static char* get_fingerprint_from_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request);



void nm_iam_init(struct nm_iam* iam, NabtoDevice* device, struct nn_log* logger)
{
    memset(iam, 0, sizeof(struct nm_iam));
    iam->device = device;
    iam->logger = logger;
    nn_vector_init(&iam->users, sizeof(void*));
    nn_vector_init(&iam->roles, sizeof(void*));
    nn_vector_init(&iam->policies, sizeof(void*));
    nm_iam_auth_handler_init(&iam->authHandler, iam->device, iam);

    init_coap_handlers(iam);
}

void nm_iam_start(struct nm_iam* iam)
{
}

void nm_iam_deinit(struct nm_iam* iam)
{
    deinit_coap_handlers(iam);

    nm_iam_auth_handler_deinit(&iam->authHandler);

    nn_vector_deinit(&iam->users);
    nn_vector_deinit(&iam->roles);
    nn_vector_deinit(&iam->policies);

    free(iam->pairingPassword);
}

bool nm_iam_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct nn_string_map* attributesIn)
{
    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint_full_hex(iam->device, ref, &fingerprint);
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

    enum nm_effect effect = NM_EFFECT_DENY;

    if (user) {
        nn_string_map_insert(&attributes, "Connection:UserId", user->id);
        effect = nm_iam_check_access_user(iam, user, action, &attributes);
    } else {
        struct nm_iam_role* unpaired = nm_iam_find_role(iam, "Unpaired");
        if (unpaired == NULL) {
            NN_LOG_ERROR(iam->logger, LOGM, "The role Unpaired does not exists, rejecting the request");
            effect = NM_EFFECT_ERROR;
        } else {
            effect = nm_iam_check_access_role(iam, unpaired, action, &attributes);
        }
    }

    bool verdict = false;
    if (effect == NM_EFFECT_ALLOW) {
        verdict = true;
    }

    const char* userId;
    if (user) {
        userId = user->id;
    } else {
        userId = "Not Paired";
    }

    NN_LOG_INFO(iam->logger, LOGM, "IAM access from the user: %s, request action: %s, verdict: %s", userId, action, verdict?"ALLOW":"DENY");

    return verdict;
}


enum nm_effect nm_iam_check_access_user(struct nm_iam* iam, struct nm_iam_user* user, const char* action, const struct nn_string_map* attributes)
{
    // go through all the users roles and associated policies, If atlease one policy ends in a rejection reject the access. If there's no rejections but an accept, then return accepted.

    const char* roleStr;
    enum nm_effect result = NM_EFFECT_NO_MATCH;
    NN_STRING_SET_FOREACH(roleStr, &user->roles)
    {
        struct nm_iam_role* role = nm_iam_find_role(iam, roleStr);
        if (role == NULL) {
            NN_LOG_ERROR(iam->logger, LOGM, "The role %s does not exists", roleStr);
            return NM_EFFECT_ERROR;
        }

        enum nm_effect e = nm_iam_check_access_role(iam, role, action, attributes);

        if (e == NM_EFFECT_ERROR || e == NM_EFFECT_DENY) {
            return e;
        }
        if (e == NM_EFFECT_ALLOW) {
            result = NM_EFFECT_ALLOW;
        }

    }
    return result;
}

enum nm_effect nm_iam_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct nn_string_map* attributes)
{
    enum nm_effect result = NM_EFFECT_NO_MATCH;
    const char* policyStr;
    NN_STRING_SET_FOREACH(policyStr, &role->policies)
    {
        struct nm_policy* policy = nm_iam_find_policy(iam, policyStr);

        enum nm_effect e = nm_policy_eval(policy, action, attributes);
        if (e == NM_EFFECT_ERROR || e == NM_EFFECT_DENY) {
            return e;
        }
        if (e == NM_EFFECT_ALLOW) {
            result = NM_EFFECT_ALLOW;
        }
    }
    return result;
}

bool nm_iam_enable_password_pairing(struct nm_iam* iam, const char* pairingPassword)
{
    iam->pairingPassword = strdup(pairingPassword);
    return true;
}

bool nm_iam_enable_remote_pairing(struct nm_iam* iam, const char* pairingServerConnectToken)
{
    nabto_device_add_server_connect_token(iam->device, pairingServerConnectToken);
    return true;
}


void init_coap_handlers(struct nm_iam* iam)
{
    nm_iam_pairing_get_init(&iam->coapPairingGetHandler, iam->device, iam);
    nm_iam_list_users_init(&iam->coapIamUsersGetHandler, iam->device, iam);
    nm_iam_pairing_password_init(&iam->coapPairingPasswordPostHandler, iam->device, iam);
    nm_iam_is_paired_init(&iam->coapPairingIsPairedGetHandler, iam->device, iam);

    nm_iam_get_user_init(&iam->coapIamUsersUserGetHandler, iam->device, iam);
    nm_iam_delete_user_init(&iam->coapIamUsersUserDeleteHandler, iam->device, iam);
    nm_iam_list_roles_init(&iam->coapIamRolesGetHandler, iam->device, iam);
    nm_iam_remove_role_from_user_init(&iam->coapIamUsersUserRolesDeleteHandler, iam->device, iam);
    nm_iam_add_role_to_user_init(&iam->coapIamUsersUserRolesPutHandler, iam->device, iam);
}

void deinit_coap_handlers(struct nm_iam* iam)
{
    nm_iam_coap_handler_deinit(&iam->coapPairingGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingPasswordPostHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingIsPairedGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingClientSettingsGetHandler);
}


struct nm_iam_user* nm_iam_find_user_by_fingerprint(struct nm_iam* iam, const char* fingerprint)
{
    struct nm_iam_user* user;
    NN_VECTOR_FOREACH(&user, &iam->users) {
        if (strcmp(user->fingerprint, fingerprint) == 0) {
            return user;
        }
    }
    return NULL;
}

struct nm_iam_role* nm_iam_find_role(struct nm_iam* iam, const char* roleStr)
{
    struct nm_iam_role* role;
    NN_VECTOR_FOREACH(&role, &iam->roles)
    {
        if (strcmp(role->id, roleStr) == 0) {
            return role;
        }
    }
    return NULL;
}
struct nm_policy* nm_iam_find_policy(struct nm_iam* iam, const char* policyStr)
{
    struct nm_policy* policy;
    NN_VECTOR_FOREACH(&policy, &iam->policies)
    {
        if (strcmp(policy->id, policyStr) == 0) {
            return policy;
        }
    }
    return NULL;
}

struct nm_iam_user* nm_iam_pair_new_client(struct nm_iam* iam, NabtoDeviceCoapRequest* request, const char* name)
{
    {
        struct nm_iam_user* user = nm_iam_find_user_by_coap_request(iam, request);
        if (user != NULL) {
            // user is already paired.
            return user;
        }
    }

    char* fingerprint = get_fingerprint_from_coap_request(iam, request);
    if (fingerprint == NULL) {
        return NULL;
    }

    const char* roleStr;

    if (nn_vector_size(&iam->users) == 0) {
        roleStr = "Admin";
    } else {
        roleStr = "User";
    }

    if (nm_iam_find_role(iam, roleStr) == NULL) {
        NN_LOG_ERROR(iam->logger, LOGM, "The role '%s' does not exists so the user cannot be paired.\n", roleStr);
        return NULL;
    }

    char* sct;
    NabtoDeviceError ec = nabto_device_create_server_connect_token(iam->device, &sct);
    if (ec != NABTO_DEVICE_EC_OK) {
        return NULL;
    }

    char* nextId = nm_iam_next_user_id(iam);
    struct nm_iam_user* user = nm_iam_user_new(nextId);
    free(nextId);

    nn_string_set_insert(&user->roles, roleStr);
    user->fingerprint = strdup(fingerprint);
    user->serverConnectToken = strdup(sct);

    nm_iam_add_user(iam, user);

    nabto_device_string_free(fingerprint);
    nabto_device_string_free(sct);

    return user;
}

bool nm_iam_add_user(struct nm_iam* iam, struct nm_iam_user* user)
{
    nn_vector_push_back(&iam->users, &user);

    if (user->serverConnectToken != NULL) {
        nabto_device_add_server_connect_token(iam->device, user->serverConnectToken);
    }

    if (iam->changeCallbacks.userChanged) {
        iam->changeCallbacks.userChanged(iam, user->id, iam->changeCallbacks.userChangedData);
    }
    return true;
}

bool nm_iam_add_role(struct nm_iam* iam, struct nm_iam_role* role)
{
    nn_vector_push_back(&iam->roles, &role);
    return true;
}

bool nm_iam_add_policy(struct nm_iam* iam, struct nm_policy* policy)
{
    nn_vector_push_back(&iam->policies, &policy);
    return true;
}

char* get_fingerprint_from_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request)
{
    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);

    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint_full_hex(iam->device, ref, &fingerprint);
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

struct nm_iam_user* nm_iam_find_user_by_id(struct nm_iam* iam, const char* id)
{
    struct nm_iam_user* user;
    NN_VECTOR_FOREACH(&user, &iam->users) {
        if (strcmp(user->id, id) == 0) {
            return user;
        }
    }
    return NULL;
}

struct nm_iam_user* nm_iam_find_user(struct nm_iam* iam, const char* id)
{
    return nm_iam_find_user_by_id(iam, id);
}

char* nm_iam_next_user_id(struct nm_iam* iam)
{
    char* id = malloc(20);
    int i = 0;

    struct nm_iam_user* user;
    do {
        memset(id, 0, 20);
        i++;
        sprintf(id, "%d", (int)i);

        user = nm_iam_find_user_by_id(iam, id);
    } while (user != NULL);

    return id;
}

void nm_iam_set_user_changed_callback(struct nm_iam* iam, nm_iam_user_changed userChanged, void* data)
{
    iam->changeCallbacks.userChanged = userChanged;
    iam->changeCallbacks.userChangedData = data;
}

bool nm_iam_get_users(struct nm_iam* iam, struct nn_string_set* ids)
{
    struct nm_iam_user* user;
    NN_VECTOR_FOREACH(&user, &iam->users)
    {
        nn_string_set_insert(ids, user->id);
    }
    return true;
}

void nm_iam_delete_user(struct nm_iam* iam, const char* userId)
{
    size_t s;
    s = nn_vector_size(&iam->users);
    for (size_t i = 0; i < s; i++) {
        struct nm_iam_user* user;
        nn_vector_get(&iam->users, i, &user);
        if (strcmp(user->id, userId) == 0) {
            nn_vector_erase(&iam->users, i);
            nm_iam_user_free(user);

            if (iam->changeCallbacks.userChanged) {
                iam->changeCallbacks.userChanged(iam, userId, iam->changeCallbacks.userChangedData);
            }

            return;
        }
    }
}


void nm_iam_enable_client_settings(struct nm_iam* iam, const char* clientServerUrl, const char* clientServerKey)
{
    iam->clientServerUrl = strdup(clientServerUrl);
    iam->clientServerKey = strdup(clientServerKey);
    nm_iam_client_settings_init(&iam->coapPairingClientSettingsGetHandler, iam->device, iam);
}

void nm_iam_remove_role_from_user(struct nm_iam* iam, const char* userId, const char* roleId)
{
    struct nm_iam_user* user = nm_iam_find_user(iam, userId);
    if (user == NULL) {
        return;
    }
    nm_iam_user_remove_role(user, roleId);

    if (iam->changeCallbacks.userChanged) {
        iam->changeCallbacks.userChanged(iam, userId, iam->changeCallbacks.userChangedData);
    }
}


bool nm_iam_add_role_to_user(struct nm_iam* iam, const char* userId, const char* roleId)
{
    struct nm_iam_user* user = nm_iam_find_user(iam, userId);
    struct nm_iam_role* role = nm_iam_find_role(iam, roleId);

    if (user == NULL || role == NULL) {
        return false;
    }

    bool status = nm_iam_user_add_role(user, roleId);

    if (status == true) {
        if (iam->changeCallbacks.userChanged) {
            iam->changeCallbacks.userChanged(iam, userId, iam->changeCallbacks.userChangedData);
        }
    }
    return status;
}
