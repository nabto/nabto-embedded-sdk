#include "iam_config.h"

#include <apps/common/json_config.h>

#include <modules/policies/nm_policy.h>
#include <modules/policies/nm_statement.h>
#include <modules/policies/nm_policies_to_json.h>
#include <modules/iam/nm_iam_role.h>
#include <modules/iam/nm_iam_to_json.h>

#include <stdio.h>

static bool create_default_iam_config(const char* iamConfigFile);

void iam_config_init(struct iam_config* iamConfig)
{
    np_vector_init(&iamConfig->roles, NULL);
    np_vector_init(&iamConfig->policies, NULL);
}

void iam_config_deinit(struct iam_config* iamConfig)
{
    np_vector_deinit(&iamConfig->roles);
    np_vector_deinit(&iamConfig->policies);
}

bool load_iam_config(struct iam_config* iamConfig, const char* iamConfigFile, const char** errorText)
{
    if (!json_config_exists(iamConfigFile)) {
        printf("IAM configuration file (%s) does not exists creating a new default file.\n", iamConfigFile);
        create_default_iam_config(iamConfigFile);
    }
    cJSON* config;
    if (json_config_load(iamConfigFile, &config)) {

    }
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

    //struct nm_iam_role* unpairedRole = nm_iam_role_new("Unpaired");

    //nm_iam_role_add_policy(unpairedRole, "PasswordPairing");


    cJSON* root = cJSON_CreateObject();

    cJSON* policies = cJSON_CreateArray();
    cJSON_AddItemToArray(policies, nm_policy_to_json(passwordPairingPolicy));
    cJSON_AddItemToArray(policies, nm_policy_to_json(tunnelAllPolicy));
    cJSON_AddItemToArray(policies, nm_policy_to_json(pairedPolicy));
    cJSON_AddItemToObject(root, "Policies", policies);


    struct nm_iam_role* unpairedRole = nm_iam_role_new("Unpaired");
    nm_iam_role_add_policy(unpairedRole, "PasswordPairing");

    struct nm_iam_role* adminRole = nm_iam_role_new("Admin");
    nm_iam_role_add_policy(adminRole, "TunnelAll");
    nm_iam_role_add_policy(adminRole, "Paired");

    struct nm_iam_role* userRole = nm_iam_role_new("User");
    nm_iam_role_add_policy(userRole, "TunnelAll");
    nm_iam_role_add_policy(userRole, "Paired");

    cJSON* roles = cJSON_CreateArray();
    cJSON_AddItemToArray(roles, nm_iam_role_to_json(unpairedRole));
    cJSON_AddItemToArray(roles, nm_iam_role_to_json(adminRole));
    cJSON_AddItemToArray(roles, nm_iam_role_to_json(userRole));
    cJSON_AddItemToObject(root, "Roles", roles);

    json_config_save(iamConfigFile, root);

    return true;
}
