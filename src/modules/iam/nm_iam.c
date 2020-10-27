#include "nm_iam.h"
#include "nm_iam_internal.h"
#include "nm_iam_user.h"
#include "nm_iam_role.h"

#include "nm_iam_coap_handler.h"

#include <nabto/nabto_device_experimental.h>
#include <modules/policies/nm_effect.h>
#include <modules/policies/nm_policy.h>

#include <nn/log.h>

#include <stdlib.h>
#include <time.h>

static const char* LOGM = "iam";

static enum nm_effect nm_iam_check_access_user(struct nm_iam* iam, struct nm_iam_user* user, const char* action, const struct nn_string_map* attributes);
static enum nm_effect nm_iam_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct nn_string_map* attributes);

static void init_coap_handlers(struct nm_iam* iam);
static void deinit_coap_handlers(struct nm_iam* iam);

static char* get_fingerprint_from_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request);



void nm_iam_init(struct nm_iam* iam, NabtoDevice* device, struct nn_log* logger)
{
    memset(iam, 0, sizeof(struct nm_iam));
    srand(time(0));
    iam->device = device;
    iam->logger = logger;
    nn_vector_init(&iam->users, sizeof(void*));
    nn_vector_init(&iam->roles, sizeof(void*));
    nn_vector_init(&iam->policies, sizeof(void*));

    nm_iam_auth_handler_init(&iam->authHandler, iam->device, iam);
    nm_iam_pake_handler_init(&iam->pakeHandler, iam->device, iam);

    init_coap_handlers(iam);
}

bool validate_role(struct nm_iam* iam, const char* role) {
    if (nm_iam_find_role(iam, role) == NULL) {
        NN_LOG_ERROR(iam->logger, LOGM, "The role '%s' does not exists in the system.\n", role);
        return false;
    }
    return true;
}

bool nm_iam_start(struct nm_iam* iam)
{
    bool ret = true;
    // validate that the pairing roles exists in the system
    ret &= validate_role(iam, iam->firstUserRole);
    ret &= validate_role(iam, iam->secondaryUserRole);
    ret &= validate_role(iam, iam->unpairedRole);
    return ret;
}

void nm_iam_deinit(struct nm_iam* iam)
{
    deinit_coap_handlers(iam);

    nm_iam_auth_handler_deinit(&iam->authHandler);
    nm_iam_pake_handler_deinit(&iam->pakeHandler);

    struct nm_iam_user* user;
    NN_VECTOR_FOREACH(&user, &iam->users) {
        nm_iam_user_free(user);
    }
    nn_vector_deinit(&iam->users);

    free(iam->firstUserRole);
    free(iam->secondaryUserRole);
    free(iam->unpairedRole);

    struct nm_iam_role* role;
    NN_VECTOR_FOREACH(&role, &iam->roles) {
        nm_iam_role_free(role);
    }
    nn_vector_deinit(&iam->roles);

    struct nm_policy* policy;
    NN_VECTOR_FOREACH(&policy, &iam->policies) {
        nm_policy_free(policy);
    }
    nn_vector_deinit(&iam->policies);

    free(iam->pairingPassword);
    free(iam->clientServerUrl);
    free(iam->clientServerKey);
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

    enum nm_effect effect = NM_EFFECT_DENY;

    if (!user && nabto_device_connection_is_password_authenticated(iam->device, ref)) {
        const char* username = nabto_device_connection_get_password_authentication_username(iam->device, ref);
        if (username != NULL) {
            // authenticated with non-empty username
            user = nm_iam_find_user_by_name(iam, username);
        }
    }
    if (user) {
        nn_string_map_insert(&attributes, "Connection:UserId", user->id);
        if (nabto_device_connection_is_local(iam->device, ref)) {
            nn_string_map_insert(&attributes, "Connection:IsLocal", "true");
        } else {
            nn_string_map_insert(&attributes, "Connection:IsLocal", "false");
        }
        effect = nm_iam_check_access_user(iam, user, action, &attributes);
    } else {
        struct nm_iam_role* role = nm_iam_find_role(iam, iam->unpairedRole);
        if (role == NULL) {
            effect = NM_EFFECT_ERROR;
        } else {
            effect = nm_iam_check_access_role(iam, role, action, &attributes);
        }
    }

    nn_string_map_deinit(&attributes);


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
    struct nm_iam_role* role = nm_iam_find_role(iam, user->role);
    if (role == NULL) {
        return NM_EFFECT_NO_MATCH;
    }
    return nm_iam_check_access_role(iam, role, action, attributes);
}

enum nm_effect nm_iam_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct nn_string_map* attributes)
{
    struct nm_policy_eval_state state;
    nm_policy_eval_init(&state);

    const char* policyStr;
    NN_STRING_SET_FOREACH(policyStr, &role->policies)
    {
        struct nm_policy* policy = nm_iam_find_policy(iam, policyStr);
        nm_policy_eval(&state, policy, action, attributes);
    }

    return nm_policy_eval_get_effect(&state);
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

bool nm_iam_set_first_user_role(struct nm_iam* iam, const char* role)
{
    if (role == NULL) {
        free(iam->firstUserRole);
        iam->firstUserRole = NULL;
        return true;
    }
    char* tmp = strdup(role);
    if (tmp != NULL) {
        free(iam->firstUserRole);
        iam->firstUserRole = tmp;
    }
    return (tmp != 0);
}

bool nm_iam_set_secondary_user_role(struct nm_iam* iam, const char* role)
{
    if (role == NULL) {
        free(iam->secondaryUserRole);
        iam->secondaryUserRole = NULL;
        return true;
    }
    char* tmp = strdup(role);
    if (tmp == NULL) {
        return false;
    }
    free(iam->secondaryUserRole);
    iam->secondaryUserRole = tmp;
    return true;
}

bool nm_iam_set_unpaired_role(struct nm_iam* iam, const char* role)
{
    if (role == NULL) {
        free(iam->unpairedRole);
        iam->unpairedRole = NULL;
        return true;
    }
    char* tmp = strdup(role);
    if (tmp == NULL) {
        return false;
    }
    free(iam->unpairedRole);
    iam->unpairedRole = tmp;
    return true;
}

void init_coap_handlers(struct nm_iam* iam)
{

    nm_iam_pairing_get_init(&iam->coapPairingGetHandler, iam->device, iam);
    nm_iam_client_settings_init(&iam->coapPairingClientSettingsGetHandler, iam->device, iam);
    nm_iam_pairing_password_init(&iam->coapPairingPasswordPostHandler, iam->device, iam);
    nm_iam_pairing_local_init(&iam->coapPairingLocalPostHandler, iam->device, iam);
    nm_iam_is_paired_init(&iam->coapPairingIsPairedGetHandler, iam->device, iam);

    nm_iam_get_me_init(&iam->coapIamMeGetHandler, iam->device, iam);
    nm_iam_list_users_init(&iam->coapIamUsersGetHandler, iam->device, iam);
    nm_iam_get_user_init(&iam->coapIamUsersUserGetHandler, iam->device, iam);
    nm_iam_create_user_init(&iam->coapIamUsersUserCreateHandler, iam->device, iam);
    nm_iam_delete_user_init(&iam->coapIamUsersUserDeleteHandler, iam->device, iam);
    nm_iam_list_roles_init(&iam->coapIamRolesGetHandler, iam->device, iam);
    nm_iam_set_user_role_init(&iam->coapIamUsersUserSetRoleHandler, iam->device, iam);
    nm_iam_set_user_name_init(&iam->coapIamUsersUserSetNameHandler, iam->device, iam);
    nm_iam_set_user_fingerprint_init(&iam->coapIamUsersUserSetFingerprintHandler, iam->device, iam);
    nm_iam_set_user_sct_init(&iam->coapIamUsersUserSetSctHandler, iam->device, iam);
    nm_iam_set_user_password_init(&iam->coapIamUsersUserSetPasswordHandler, iam->device, iam);
}

void deinit_coap_handlers(struct nm_iam* iam)
{
    nm_iam_coap_handler_deinit(&iam->coapPairingGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingPasswordPostHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingLocalPostHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingIsPairedGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingClientSettingsGetHandler);

    nm_iam_coap_handler_deinit(&iam->coapIamMeGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserCreateHandler);

    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserDeleteHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamRolesGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserSetRoleHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersUserSetNameHandler);
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
    NN_VECTOR_FOREACH(&user, &iam->users) {
        if (user->fingerprint != NULL && strcmp(user->fingerprint, fingerprint) == 0) {
            return user;
        }
    }
    return NULL;
}

struct nm_iam_user* nm_iam_find_user_by_name(struct nm_iam* iam, const char* name)
{
    if (name == NULL) {
        return NULL;
    }
    struct nm_iam_user* user;
    NN_VECTOR_FOREACH(&user, &iam->users) {
        if (user->name != NULL && strcmp(user->name, name) == 0) {
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
    if (policyStr == NULL) {
        return NULL;
    }
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

    bool firstUser = (nn_vector_size(&iam->users) == 0);

    char* sct;
    NabtoDeviceError ec = nabto_device_create_server_connect_token(iam->device, &sct);
    if (ec != NABTO_DEVICE_EC_OK) {
        return NULL;
    }

    char* nextId = nm_iam_make_user_id(iam);
    struct nm_iam_user* user = nm_iam_user_new(nextId);
    free(nextId);

    if (firstUser) {
        nm_iam_user_set_role(user, iam->firstUserRole);
    } else {
        nm_iam_user_set_role(user, iam->secondaryUserRole);
    }

    nm_iam_user_set_fingerprint(user, fingerprint);
    nm_iam_user_set_server_connect_token(user, sct);
    if (name != NULL) {
        nm_iam_user_set_name(user, name);
    }

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

char* nm_iam_make_user_id(struct nm_iam* iam)
{
    char* id = malloc(7);

    struct nm_iam_user* user;
    do {
        memset(id, 0, 7);
        for (int i = 0; i<6; i++) {
            sprintf(id+i, "%c", (char)('a'+rand()%26));
        }

        user = nm_iam_find_user_by_id(iam, id);
    } while (user != NULL);

    return id;
}

char* nm_iam_make_user_name(struct nm_iam* iam, const char* suggested)
{
    if (nm_iam_find_user_by_name(iam, suggested) == NULL) {
        return strdup(suggested);
    }
    char* name = malloc(strlen(suggested)+20);
    strcpy(name, suggested);
    char* suffix = name+strlen(suggested);
    int i = 0;
    struct nm_iam_user* user;
    do {
        memset(suffix, 0, 20);
        i++;
        sprintf(suffix, "-%d", (int)i);
        user = nm_iam_find_user_by_name(iam, name);
    } while (user != NULL);
    return name;
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


bool nm_iam_set_user_role(struct nm_iam* iam, const char* userId, const char* roleId)
{
    struct nm_iam_user* user = nm_iam_find_user(iam, userId);
    struct nm_iam_role* role = nm_iam_find_role(iam, roleId);

    if (user == NULL || role == NULL) {
        return false;
    }

    bool status = nm_iam_user_set_role(user, roleId);

    if (status == true) {
        if (iam->changeCallbacks.userChanged) {
            iam->changeCallbacks.userChanged(iam, userId, iam->changeCallbacks.userChangedData);
        }
    }
    return status;
}
