#include "iam_config.h"

#include <apps/common/json_config.h>

#include <modules/policies/nm_policy.h>
#include <modules/policies/nm_statement.h>
#include <modules/policies/nm_condition.h>
#include <modules/policies/nm_policies_to_json.h>
#include <modules/policies/nm_policies_from_json.h>
#include <modules/iam/nm_iam_role.h>
#include <modules/iam/nm_iam_to_json.h>
#include <modules/iam/nm_iam_from_json.h>

#include <stdio.h>

static const char* LOGM = "iam_config";

static bool create_default_iam_config(const char* iamConfigFile);

void iam_config_init(struct iam_config* iamConfig)
{
    nn_vector_init(&iamConfig->roles, sizeof(void*));
    nn_vector_init(&iamConfig->policies, sizeof(void*));
    nn_string_set_init(&iamConfig->unpairedRoles);
    nn_string_set_init(&iamConfig->firstUserRoles);
    nn_string_set_init(&iamConfig->secondaryUserRoles);
}

void iam_config_deinit(struct iam_config* iamConfig)
{
    nn_vector_deinit(&iamConfig->roles);
    nn_vector_deinit(&iamConfig->policies);
    nn_string_set_deinit(&iamConfig->unpairedRoles);
    nn_string_set_deinit(&iamConfig->firstUserRoles);
    nn_string_set_deinit(&iamConfig->secondaryUserRoles);
}

static bool read_roles(struct nn_log* logger, cJSON* roles, struct nn_string_set* set)
{
    if (!cJSON_IsArray(roles)) {
        return false;
    }
    size_t rolesSize = cJSON_GetArraySize(roles);
    for(size_t i = 0; i < rolesSize; i++) {
        cJSON* item = cJSON_GetArrayItem(roles, i);
        if (!cJSON_IsString(item)) {
            return false;
        }
        nn_string_set_insert(set, item->valuestring);
    }
    return true;
}

bool load_iam_config(struct iam_config* iamConfig, const char* iamConfigFile, struct nn_log* logger)
{
    if (!json_config_exists(iamConfigFile)) {
        NN_LOG_INFO(logger, LOGM, "IAM configuration file (%s) does not exists creating a new default file.", iamConfigFile);
        create_default_iam_config(iamConfigFile);
    }

    cJSON* root;
    if (!json_config_load(iamConfigFile, &root, logger)) {
        return false;
    }

    if (!cJSON_IsObject(root)) {
        NN_LOG_ERROR(logger, LOGM, "Invalid IAM root format");
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
        return false;
    }

    if (!cJSON_IsNumber(version)) {
        NN_LOG_ERROR(logger, LOGM, "missing version in iam config, try to delete %s to make a new default file", iamConfigFile);
        return false;
    }

    if (version->valueint != 1) {
        NN_LOG_ERROR(logger, LOGM, "Unsupported iam config version. Version %d is not supported", version->valueint);
        return false;
    }


    if (!cJSON_IsObject(config)) {
        NN_LOG_ERROR(logger, LOGM, "Missing config");
    }

    size_t policiesSize = cJSON_GetArraySize(policies);
    for (size_t i = 0; i < policiesSize; i++) {
        cJSON* item = cJSON_GetArrayItem(policies, i);
        struct nm_policy* policy = nm_policy_from_json(item, logger);
        if (policy == NULL) {
            return false;
        }
        nn_vector_push_back(&iamConfig->policies, &policy);
    }

    size_t rolesSize = cJSON_GetArraySize(roles);
    for(size_t i = 0; i < rolesSize; i++) {
        cJSON* item = cJSON_GetArrayItem(roles, i);
        struct nm_iam_role* role = nm_iam_role_from_json(item);
        if (role == NULL) {
            return false;
        }
        nn_vector_push_back(&iamConfig->roles, &role);
    }

    cJSON* unpairedRoles = cJSON_GetObjectItem(config, "UnpairedRoles");
    cJSON* firstUserRoles = cJSON_GetObjectItem(config, "FirstUserRoles");
    cJSON* secondaryUserRoles = cJSON_GetObjectItem(config, "SecondaryUserRoles");

    if (unpairedRoles && !read_roles(logger, unpairedRoles, &iamConfig->unpairedRoles)) {
        NN_LOG_ERROR(logger, LOGM, "Config.UnpairedRoles has the wrong format.");
    }

    if (firstUserRoles && !read_roles(logger, firstUserRoles, &iamConfig->firstUserRoles)) {
        NN_LOG_ERROR(logger, LOGM, "Config.UnpairedRoles has the wrong format.");
    }

    if (secondaryUserRoles && !read_roles(logger, secondaryUserRoles, &iamConfig->secondaryUserRoles)) {
        NN_LOG_ERROR(logger, LOGM, "Config.UnpairedRoles has the wrong format.");
    }




    cJSON_Delete(root);
    return true;
}

bool create_default_iam_config(const char* iamConfigFile)
{
    struct nm_policy* pairingPolicy = nm_policy_new("Pairing");
    {
        struct nm_statement* stmt = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(stmt, "Pairing:Get");
        nm_statement_add_action(stmt, "Pairing:Password");
        nm_statement_add_action(stmt, "Pairing:Local");
        nm_policy_add_statement(pairingPolicy, stmt);
    }

    struct nm_policy* tunnellingPolicy = nm_policy_new("Tunnelling");
    {
        struct nm_statement* stmt = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(stmt, "TcpTunnel:GetService");
        nm_statement_add_action(stmt, "TcpTunnel:Connect");
        nm_statement_add_action(stmt, "TcpTunnel:ListServices");
        nm_policy_add_statement(tunnellingPolicy, stmt);
    }

    struct nm_policy* manageUsers = nm_policy_new("ManageUsers");
    {
        struct nm_statement* stmt = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(stmt, "IAM:ListUsers");
        nm_statement_add_action(stmt, "IAM:GetUser");
        nm_statement_add_action(stmt, "IAM:DeleteUser");
        nm_statement_add_action(stmt, "IAM:AddRoleToUser");
        nm_statement_add_action(stmt, "IAM:RemoveRoleFromUser");
        nm_statement_add_action(stmt, "IAM:ListRoles");
        nm_policy_add_statement(manageUsers, stmt);
    }

    struct nm_policy* manageOwnUser = nm_policy_new("ManageOwnUser");
    {
        struct nm_statement* stmt = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(stmt, "IAM:GetUser");
        nm_statement_add_action(stmt, "IAM:DeleteUser");
        struct nm_condition* c = nm_condition_new_with_key(NM_CONDITION_OPERATOR_STRING_EQUALS, "IAM:UserId");
        nm_condition_add_value(c, "${Connection:UserId}");
        nm_statement_add_condition(stmt, c);
        nm_policy_add_statement(manageOwnUser, stmt);
    }

    struct nm_iam_role* unpairedRole = nm_iam_role_new("Unpaired");
    nm_iam_role_add_policy(unpairedRole, "Pairing");

    struct nm_iam_role* adminRole = nm_iam_role_new("Admin");
    nm_iam_role_add_policy(adminRole, "ManageUsers");

    struct nm_iam_role* userRole = nm_iam_role_new("User");
    nm_iam_role_add_policy(userRole, "Tunnelling");
    nm_iam_role_add_policy(userRole, "Pairing");
    nm_iam_role_add_policy(userRole, "ManageOwnUser");


    // Write Iam policies to json.
    cJSON* root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "Version", 1);

    cJSON* policies = cJSON_CreateArray();
    cJSON_AddItemToArray(policies, nm_policy_to_json(pairingPolicy));
    cJSON_AddItemToArray(policies, nm_policy_to_json(tunnellingPolicy));
    cJSON_AddItemToArray(policies, nm_policy_to_json(manageUsers));
    cJSON_AddItemToArray(policies, nm_policy_to_json(manageOwnUser));
    cJSON_AddItemToObject(root, "Policies", policies);

    // Write default roles to json
    cJSON* roles = cJSON_CreateArray();
    cJSON_AddItemToArray(roles, nm_iam_role_to_json(unpairedRole));
    cJSON_AddItemToArray(roles, nm_iam_role_to_json(adminRole));
    cJSON_AddItemToArray(roles, nm_iam_role_to_json(userRole));
    cJSON_AddItemToObject(root, "Roles", roles);

    // Write iam config to json
    cJSON* config = cJSON_CreateObject();

    cJSON* unpairedRoles = cJSON_CreateStringArray((const char*[]){"Unpaired"}, 1);
    cJSON* firstUserRoles = cJSON_CreateStringArray((const char*[]){"Admin", "User"}, 2);
    cJSON* secondaryUserRoles = cJSON_CreateStringArray((const char*[]){"User"}, 1);

    cJSON_AddItemToObject(config, "UnpairedRoles", unpairedRoles);
    cJSON_AddItemToObject(config, "FirstUserRoles", firstUserRoles);
    cJSON_AddItemToObject(config, "SecondaryUserRoles", secondaryUserRoles);

    cJSON_AddItemToObject(root, "Config", config);

    json_config_save(iamConfigFile, root);

    cJSON_Delete(root);

    return true;
}
