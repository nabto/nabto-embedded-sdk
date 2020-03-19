#include "nm_iam.h"
#include "nm_iam_user.h"
#include "nm_iam_role.h"

#include "nm_iam_coap_handler.h"

#include <modules/policies/nm_effect.h>
#include <modules/policies/nm_policy.h>

#include <stdlib.h>


static enum nm_effect nm_iam_check_access_user(struct nm_iam* iam, struct nm_iam_user* user, const char* action, const struct np_string_map* attributes);
static enum nm_effect nm_iam_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct np_string_map* attributes);

static void init_coap_handlers(struct nm_iam* iam);
static void deinit_coap_handlers(struct nm_iam* iam);

static char* get_fingerprint_from_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request);
static struct nm_iam_user* find_user_by_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request);


void nm_iam_init(struct nm_iam* iam, NabtoDevice* device)
{
    iam->device = device;
    np_vector_init(&iam->users, NULL);
    np_vector_init(&iam->roles, NULL);
    np_vector_init(&iam->policies, NULL);

    nm_iam_auth_handler_init(&iam->authHandler, device, iam);

    init_coap_handlers(iam);
}

void nm_iam_deinit(struct nm_iam* iam)
{
    deinit_coap_handlers(iam);

    nm_iam_auth_handler_deinit(&iam->authHandler);

    np_vector_deinit(&iam->users);
    np_vector_deinit(&iam->roles);
    np_vector_deinit(&iam->policies);

    free(iam->pairingPassword);
}

bool nm_iam_check_access(struct nm_iam* iam, NabtoDeviceConnectionRef ref, const char* action, const struct np_string_map* attributesIn)
{
    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint_full_hex(iam->device, ref, &fingerprint);
    if (ec) {
        return false;
    }

    struct np_string_map attributes;
    np_string_map_init(&attributes);


    if (attributesIn) {
        struct np_string_map_item* item;
        NP_STRING_MAP_FOREACH(item, attributesIn) {
            np_string_map_insert(&attributes, item->key, item->value);
        }
    }

    struct nm_iam_user* user = nm_iam_find_user_by_fingerprint(iam, fingerprint);
    nabto_device_string_free(fingerprint);

    enum nm_effect effect;

    if (user) {
        np_string_map_insert(&attributes, "Connection:UserId", user->id);
        effect = nm_iam_check_access_user(iam, user, action, &attributes);
    } else {
        effect = nm_iam_check_access_role(iam, iam->unpairedRole, action, &attributes);
    }

    bool verdict = false;
    if (effect == NM_EFFECT_ALLOW) {
        verdict = true;
    }

    return verdict;
}


enum nm_effect nm_iam_check_access_user(struct nm_iam* iam, struct nm_iam_user* user, const char* action, const struct np_string_map* attributes)
{
    // go through all the users roles and associated policies, If atlease one policy ends in a rejection reject the access. If there's no rejections but an accept, then return accepted.

    const char* roleStr;
    enum nm_effect result = NM_EFFECT_NO_MATCH;
    NP_STRING_SET_FOREACH(roleStr, &user->roles)
    {
        struct nm_iam_role* role = nm_iam_find_role(iam, roleStr);

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

enum nm_effect nm_iam_check_access_role(struct nm_iam* iam, struct nm_iam_role* role, const char* action, const struct np_string_map* attributes)
{
    enum nm_effect result = NM_EFFECT_NO_MATCH;
    const char* policyStr;
    NP_STRING_SET_FOREACH(policyStr, &role->policies)
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
}

void deinit_coap_handlers(struct nm_iam* iam)
{
    nm_iam_coap_handler_deinit(&iam->coapPairingGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapIamUsersGetHandler);
    nm_iam_coap_handler_deinit(&iam->coapPairingPasswordPostHandler);
}


struct nm_iam_user* nm_iam_find_user_by_fingerprint(struct nm_iam* iam, const char* fingerprint)
{
    struct nm_iam_user* user;
    NP_VECTOR_FOREACH(user, &iam->users) {
        if (strcmp(user->fingerprint, fingerprint) == 0) {
            return user;
        }
    }
    return NULL;
}

struct nm_iam_role* nm_iam_find_role(struct nm_iam* iam, const char* roleStr)
{
    struct nm_iam_role* role;
    NP_VECTOR_FOREACH(role, &iam->roles)
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
    NP_VECTOR_FOREACH(policy, &iam->policies)
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
        struct nm_iam_user* user = find_user_by_coap_request(iam, request);
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

    if (np_vector_size(&iam->users) == 0) {
        roleStr = "Admin";
    } else {
        roleStr = "User";
    }

    if (nm_iam_find_role(iam, roleStr) == NULL) {
        printf("Warning missing the Role '%s' so the user cannot be paired.\n", roleStr);
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

    np_string_set_add(&user->roles, roleStr);
    user->fingerprint = strdup(fingerprint);
    user->serverConnectToken = strdup(sct);

    np_vector_push_back(&iam->users, user);

    nabto_device_string_free(fingerprint);
    nabto_device_string_free(sct);
    return user;
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

struct nm_iam_user* find_user_by_coap_request(struct nm_iam* iam, NabtoDeviceCoapRequest* request)
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
    NP_VECTOR_FOREACH(user, &iam->users) {
        if (strcmp(user->id, id) == 0) {
            return user;
        }
    }
    return NULL;
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
