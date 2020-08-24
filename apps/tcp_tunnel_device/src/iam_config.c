#include "iam_config.h"

#include <apps/common/json_config.h>

#include <modules/policies/nm_policy.h>
#include <modules/policies/nm_statement.h>
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
}

void iam_config_deinit(struct iam_config* iamConfig)
{
    nn_vector_deinit(&iamConfig->roles);
    nn_vector_deinit(&iamConfig->policies);
}

bool load_iam_config(struct iam_config* iamConfig, const char* iamConfigFile, struct nn_log* logger)
{
    if (!json_config_exists(iamConfigFile)) {
        NN_LOG_INFO(logger, LOGM, "IAM configuration file (%s) does not exists creating a new default file.", iamConfigFile);
        create_default_iam_config(iamConfigFile);
    }

    cJSON* config;
    if (!json_config_load(iamConfigFile, &config, logger)) {
        return false;
    }

    if (!cJSON_IsObject(config)) {
        NN_LOG_ERROR(logger, LOGM, "Invalid IAM config format");
        return false;
    }

    cJSON* policies = cJSON_GetObjectItem(config, "Policies");
    cJSON* roles = cJSON_GetObjectItem(config, "Roles");

    if (!cJSON_IsArray(policies) ||
        !cJSON_IsArray(roles))
    {
        NN_LOG_ERROR(logger, LOGM, "missing policies or roles");
        return false;
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
    cJSON_Delete(config);
    return true;
}

bool create_default_iam_config(const char* iamConfigFile)
{
    struct nm_policy* passwordPairingPolicy = nm_policy_new("PasswordPairing");
    {
        struct nm_statement* stmt = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(stmt, "Pairing:Get");
        nm_statement_add_action(stmt, "Pairing:Password");
        nm_policy_add_statement(passwordPairingPolicy, stmt);
    }

    struct nm_policy* localPairingPolicy = nm_policy_new("LocalPairing");
    {
        struct nm_statement* stmt = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(stmt, "Pairing:Get");
        nm_statement_add_action(stmt, "Pairing:Local");
        nm_policy_add_statement(localPairingPolicy, stmt);
    }

    struct nm_policy* tunnelAllPolicy = nm_policy_new("TunnelAll");
    {
        struct nm_statement* stmt = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(stmt, "TcpTunnel:GetService");
        nm_statement_add_action(stmt, "TcpTunnel:Connect");
        nm_statement_add_action(stmt, "TcpTunnel:ListServices");
        nm_policy_add_statement(tunnelAllPolicy, stmt);
    }

    struct nm_policy* pairedPolicy = nm_policy_new("Paired");
    {
        struct nm_statement* stmt = nm_statement_new(NM_EFFECT_ALLOW);
        nm_statement_add_action(stmt, "Pairing:Get");
        nm_policy_add_statement(pairedPolicy, stmt);
    }

    //struct nm_iam_role* unnairedRole = nm_iam_role_new("Unnaired");

    //nm_iam_role_add_policy(unnairedRole, "PasswordPairing");


    cJSON* root = cJSON_CreateObject();

    cJSON* policies = cJSON_CreateArray();
    cJSON_AddItemToArray(policies, nm_policy_to_json(passwordPairingPolicy));
    cJSON_AddItemToArray(policies, nm_policy_to_json(localPairingPolicy));
    cJSON_AddItemToArray(policies, nm_policy_to_json(tunnelAllPolicy));
    cJSON_AddItemToArray(policies, nm_policy_to_json(pairedPolicy));
    cJSON_AddItemToObject(root, "Policies", policies);


    struct nm_iam_role* unpairedRole = nm_iam_role_new("Unpaired");
    nm_iam_role_add_policy(unpairedRole, "PasswordPairing");
    nm_iam_role_add_policy(unpairedRole, "LocalPairing");

    struct nm_iam_role* adminRole = nm_iam_role_new("Admin");
    nm_iam_role_add_policy(adminRole, "TunnelAll");
    nm_iam_role_add_policy(adminRole, "Paired");
    nm_iam_role_add_policy(adminRole, "PasswordPairing");
    nm_iam_role_add_policy(adminRole, "LocalPairing");

    struct nm_iam_role* userRole = nm_iam_role_new("User");
    nm_iam_role_add_policy(userRole, "TunnelAll");
    nm_iam_role_add_policy(userRole, "Paired");
    nm_iam_role_add_policy(userRole, "PasswordPairing");
    nm_iam_role_add_policy(userRole, "LocalPairing");

    cJSON* roles = cJSON_CreateArray();
    cJSON_AddItemToArray(roles, nm_iam_role_to_json(unpairedRole));
    cJSON_AddItemToArray(roles, nm_iam_role_to_json(adminRole));
    cJSON_AddItemToArray(roles, nm_iam_role_to_json(userRole));
    cJSON_AddItemToObject(root, "Roles", roles);

    json_config_save(iamConfigFile, root);

    cJSON_Delete(root);

    return true;
}
