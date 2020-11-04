#include "nm_iam_serializer.h"

#include "policies/nm_policies_to_json.h"
#include "policies/nm_policies_from_json.h"
#include "nm_iam_to_json.h"
#include "nm_iam_from_json.h"

#include <cjson/cJSON.h>

static const char* LOGM = "nm_iam_serializer";

bool nm_iam_serializer_configuration_dump_json(struct nm_iam_configuration* conf, char** out)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "Version", 1);

    cJSON* policies = cJSON_CreateArray();
    struct nm_iam_policy* p;
    NN_LLIST_FOREACH(p, &conf->policies) {
        cJSON_AddItemToArray(policies, nm_policy_to_json(p));
    }
    cJSON_AddItemToObject(root, "Policies", policies);

    cJSON* roles = cJSON_CreateArray();
    struct nm_iam_role* r;
    NN_LLIST_FOREACH(r, &conf->roles) {
        cJSON_AddItemToArray(roles, nm_iam_role_to_json(r));
    }
    cJSON_AddItemToObject(root, "Roles", roles);

    cJSON* config = cJSON_CreateObject();
    cJSON_AddStringToObject(config, "UnpairedRole", conf->unpairedRole);
    cJSON_AddStringToObject(config, "FirstUserRole", conf->firstUserRole);
    cJSON_AddStringToObject(config, "SecondaryUserRole", conf->secondaryUserRole);

    cJSON_AddItemToObject(root, "Config", config);

    char* j = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (j != NULL) {
        *out = j;
        return true;
    }
    return false;
}

bool nm_iam_serializer_configuration_load_json(struct nm_iam_configuration* conf, const char* in, struct nn_log* logger)
{
    cJSON* root = cJSON_Parse(in);
    if (root == NULL) {
        const char* error = cJSON_GetErrorPtr();
        if (error != NULL) {
            NN_LOG_ERROR(logger, LOGM, "JSON parse error: %s", error);
        }

    }
    if (!cJSON_IsObject(root)) {
        NN_LOG_ERROR(logger, LOGM, "Invalid IAM root format");
        cJSON_Delete(root);
        return false;
    }

    cJSON* version = cJSON_GetObjectItem(root, "Version");
    cJSON* policies = cJSON_GetObjectItem(root, "Policies");
    cJSON* roles = cJSON_GetObjectItem(root, "Roles");
    cJSON* config = cJSON_GetObjectItem(root, "Config");

    if (!cJSON_IsArray(policies) ||
        !cJSON_IsArray(roles))
    {
        NN_LOG_ERROR(logger, LOGM, "missing policies or roles");
        cJSON_Delete(root);
        return false;
    }

    if (!cJSON_IsNumber(version)) {
        NN_LOG_ERROR(logger, LOGM, "missing version in iam config");
        cJSON_Delete(root);
        return false;
    }

    if (version->valueint != 1) {
        NN_LOG_ERROR(logger, LOGM, "Unsupported iam config version. Version %d is not supported", version->valueint);
        cJSON_Delete(root);
        return false;
    }


    if (!cJSON_IsObject(config)) {
        NN_LOG_ERROR(logger, LOGM, "Missing config");
        cJSON_Delete(root);
        return false;
    }

    size_t policiesSize = cJSON_GetArraySize(policies);
    for (size_t i = 0; i < policiesSize; i++) {
        cJSON* item = cJSON_GetArrayItem(policies, i);
        struct nm_iam_policy* policy = nm_policy_from_json(item, logger);
        if (policy == NULL) {
            cJSON_Delete(root);
            return false;
        }
        nm_iam_configuration_add_policy(conf, policy);
    }

    size_t rolesSize = cJSON_GetArraySize(roles);
    for(size_t i = 0; i < rolesSize; i++) {
        cJSON* item = cJSON_GetArrayItem(roles, i);
        struct nm_iam_role* role = nm_iam_role_from_json(item);
        if (role == NULL) {
            cJSON_Delete(root);
            return false;
        }
        nm_iam_configuration_add_role(conf, role);
    }

    cJSON* unpairedRole = cJSON_GetObjectItem(config, "UnpairedRole");
    cJSON* firstUserRole = cJSON_GetObjectItem(config, "FirstUserRole");
    cJSON* secondaryUserRole = cJSON_GetObjectItem(config, "SecondaryUserRole");
    cJSON* initialUserUsername = cJSON_GetObjectItem(config, "InitialUserUsername");

    if (unpairedRole) {
        if (!cJSON_IsString(unpairedRole)) {
            NN_LOG_ERROR(logger, LOGM, "Config.UnpairedRole has the wrong format.");
        } else {
            nm_iam_configuration_set_unpaired_role(conf, unpairedRole->valuestring);
        }
    }

    if (firstUserRole) {
        if (!cJSON_IsString(firstUserRole)) {
            NN_LOG_ERROR(logger, LOGM, "Config.UnpairedRole has the wrong format.");
        } else {
            nm_iam_configuration_set_first_user_role(conf, firstUserRole->valuestring);
        }
    }

    if (secondaryUserRole) {
        if (!cJSON_IsString(secondaryUserRole)) {
            NN_LOG_ERROR(logger, LOGM, "Config.UnpairedRole has the wrong format.");
        } else {
            nm_iam_configuration_set_secondary_user_role(conf, secondaryUserRole->valuestring);
        }
    }

    if (initialUserUsername) {
        if (!cJSON_IsString(initialUserUsername)) {
            NN_LOG_ERROR(logger, LOGM, "Config.InitialUserUsername has the wrong format.");
        } else {
            nm_iam_configuration_set_initial_user_username(conf, initialUserUsername->valuestring);
        } 
    }

    cJSON_Delete(root);
    return true;
}

/**
 * Dump the IAM state to a JSON string for persistent storage. The
 * resulting string must be freed with
 * nm_iam_serializer_string_free().
 *
 * @param state [in]  State to dump from
 * @param out [out]   Where to put serialized state
 * @return true iff the state was serialized successfully
 */
bool nm_iam_serializer_state_dump_json(struct nm_iam_state* state, char** out)
{
    cJSON* json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "Version", 1);
    if (state == NULL) {
        cJSON* usersArray = cJSON_CreateArray();
        cJSON_AddItemToObject(json, "Users", usersArray);

    } else {
        if (state->globalPairingPassword) {
            cJSON_AddItemToObject(json, "PairingPassword", cJSON_CreateString(state->globalPairingPassword));
        }
        if (state->globalSct) {
            cJSON_AddItemToObject(json, "PairingServerConnectToken", cJSON_CreateString(state->globalSct));
        }

        cJSON* usersArray = cJSON_CreateArray();

        struct nm_iam_user* user;
        NN_LLIST_FOREACH(user, &state->users)
        {
            cJSON* encodedUser = nm_iam_user_to_json(user);
            cJSON_AddItemToArray(usersArray, encodedUser);
        }
        cJSON_AddItemToObject(json, "Users", usersArray);
    }
    char* j = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (j != NULL) {
        *out = j;
        return true;
    }
    return false;
}

/**
 * Load the IAM state from a JSON string.
 *
 * @param state [in]  State to load into
 * @param in [in]     JSON string to load
 * @return true iff the state was successfully loaded
 */
bool nm_iam_serializer_state_load_json(struct nm_iam_state* state, const char* in, struct nn_log* logger)
{
    cJSON* root = cJSON_Parse(in);
    if (root == NULL) {
        const char* error = cJSON_GetErrorPtr();
        if (error != NULL) {
            NN_LOG_ERROR(logger, LOGM, "JSON parse error: %s", error);
        }
        return false;
    }
    if (!cJSON_IsObject(root)) {
        NN_LOG_ERROR(logger, LOGM, "Invalid IAM root format");
        cJSON_Delete(root);
        return false;
    }

    cJSON* version = cJSON_GetObjectItem(root, "Version");
    cJSON* pairingPassword = cJSON_GetObjectItem(root, "PairingPassword");
    cJSON* pairingServerConnectToken = cJSON_GetObjectItem(root, "PairingServerConnectToken");
    cJSON* users = cJSON_GetObjectItem(root, "Users");

    if (!cJSON_IsNumber(version)) {
        NN_LOG_ERROR(logger, LOGM, "missing version in iam state");
        cJSON_Delete(root);
        return false;
    }

    if (pairingPassword != NULL && cJSON_IsString(pairingPassword)) {
        nm_iam_state_set_pairing_password(state, pairingPassword->valuestring);
    }

    if (pairingServerConnectToken != NULL && cJSON_IsString(pairingServerConnectToken)) {
        nm_iam_state_set_pairing_server_connect_token(state, pairingServerConnectToken->valuestring);
    }

    if (users != NULL && cJSON_IsArray(users)) {

        size_t usersSize = cJSON_GetArraySize(users);
        for (size_t i = 0; i < usersSize; i++) {
            cJSON* item = cJSON_GetArrayItem(users, i);
            struct nm_iam_user* user = nm_iam_user_from_json(item);
            if (user != NULL) {
                nm_iam_state_add_user(state, user);
            }
        }
    }
    cJSON_Delete(root);
    return true;
}

void nm_iam_serializer_string_free(char* string)
{
    free(string);
}
