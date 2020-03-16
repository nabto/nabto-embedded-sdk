#include "tcp_tunnel_default_policies.h"

#include <apps/common/json_config.h>

#include <modules/policies/nm_policy.h>
#include <modules/policies/nm_statement.h>
#include <modules/policies/nm_policies_to_json.h>

#include <cjson/cJSON.h>

bool init_default_policies(const char* policiesFile)
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



    return true;
}
