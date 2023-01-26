#include "iam_config.h"

#include <apps/common/string_file.h>

#include <modules/iam/nm_iam_serializer.h>

#include <stdio.h>
#include <string.h>

static const char* LOGM = "iam_config";

bool iam_config_exists(struct nm_file* fileImpl, const char* iamConfigFile) {
    return string_file_exists(fileImpl, iamConfigFile);
}

bool iam_config_load(struct nm_iam_configuration* iamConfig, struct nm_file* fileImpl, const char* iamConfigFile, struct nn_log* logger)
{
    char* str;
    if (!string_file_load(fileImpl, iamConfigFile, &str)) {
        return false;
    }

    if (!nm_iam_serializer_configuration_load_json(iamConfig, str, logger)) {
        NN_LOG_ERROR(logger, LOGM, "Loading config failed, try to delete %s to make a new default file", iamConfigFile);
        free(str);
        return false;
    }
    free(str);
    return true;
}

bool iam_config_create_default(struct nm_file* fileImpl, const char* iamConfigFile)
{
    struct nm_iam_configuration* iamConfig = nm_iam_configuration_new();

    struct nm_iam_policy* policy;
    struct nm_iam_statement* stmt;
    {
        policy = nm_iam_configuration_policy_new("Pairing");
        stmt = nm_iam_configuration_policy_create_statement(policy, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(stmt, "IAM:GetPairing");
        nm_iam_configuration_statement_add_action(stmt, "IAM:PairingPasswordInvite");
        nm_iam_configuration_statement_add_action(stmt, "IAM:PairingLocalInitial");
        nm_iam_configuration_statement_add_action(stmt, "IAM:PairingLocalOpen");
        nm_iam_configuration_statement_add_action(stmt, "IAM:PairingPasswordOpen");
        nm_iam_configuration_add_policy(iamConfig, policy);
    }

    {
        policy = nm_iam_configuration_policy_new("Tunnelling");
        stmt = nm_iam_configuration_policy_create_statement(policy, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(stmt, "TcpTunnel:GetService");
        nm_iam_configuration_statement_add_action(stmt, "TcpTunnel:Connect");
        nm_iam_configuration_statement_add_action(stmt, "TcpTunnel:ListServices");
        nm_iam_configuration_add_policy(iamConfig, policy);
    }

    {
        policy = nm_iam_configuration_policy_new("ManageIAM");
        stmt = nm_iam_configuration_policy_create_statement(policy, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(stmt, "IAM:ListUsers");
        nm_iam_configuration_statement_add_action(stmt, "IAM:GetUser");
        nm_iam_configuration_statement_add_action(stmt, "IAM:DeleteUser");
        nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserRole");
        nm_iam_configuration_statement_add_action(stmt, "IAM:ListRoles");
        nm_iam_configuration_statement_add_action(stmt, "IAM:CreateUser");
        nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserPassword");
        nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserDisplayName");
        nm_iam_configuration_statement_add_action(stmt, "IAM:SetSettings");
        nm_iam_configuration_statement_add_action(stmt, "IAM:GetSettings");
        nm_iam_configuration_statement_add_action(stmt, "IAM:SetDeviceInfo");
        nm_iam_configuration_add_policy(iamConfig, policy);
    }

    {
        policy = nm_iam_configuration_policy_new("ManageOwnUser");
        {
            stmt = nm_iam_configuration_policy_create_statement(policy, NM_IAM_EFFECT_ALLOW);
            nm_iam_configuration_statement_add_action(stmt, "IAM:GetUser");
            nm_iam_configuration_statement_add_action(stmt, "IAM:DeleteUser");
            nm_iam_configuration_statement_add_action(stmt, "IAM:SetUserDisplayName");
            struct nm_iam_condition* c = nm_iam_configuration_statement_create_condition(stmt, NM_IAM_CONDITION_OPERATOR_STRING_EQUALS, "IAM:Username");
            nm_iam_configuration_condition_add_value(c, "${Connection:Username}");
        }
        {
            stmt = nm_iam_configuration_policy_create_statement(policy, NM_IAM_EFFECT_ALLOW);
            nm_iam_configuration_statement_add_action(stmt, "IAM:ListRoles");
            nm_iam_configuration_statement_add_action(stmt, "IAM:ListUsers");
        }
        nm_iam_configuration_add_policy(iamConfig, policy);
    }

    struct nm_iam_role* r;
    {
        r = nm_iam_configuration_role_new("Unpaired");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_add_role(iamConfig, r);
    }

    {
        r = nm_iam_configuration_role_new("Administrator");
        nm_iam_configuration_role_add_policy(r, "ManageIAM");
        nm_iam_configuration_role_add_policy(r, "Tunnelling");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_add_role(iamConfig, r);
    }

    {
        r = nm_iam_configuration_role_new("Standard");
        nm_iam_configuration_role_add_policy(r, "Tunnelling");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_role_add_policy(r, "ManageOwnUser");
        nm_iam_configuration_add_role(iamConfig, r);
    }

    {
        r = nm_iam_configuration_role_new("Guest");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_role_add_policy(r, "ManageOwnUser");
        nm_iam_configuration_add_role(iamConfig, r);
    }

    nm_iam_configuration_set_unpaired_role(iamConfig, "Unpaired");

    bool status = true;
    char* str = NULL;
    if (!nm_iam_serializer_configuration_dump_json(iamConfig, &str)) {
        status = false;
    } else if(!string_file_save(fileImpl, iamConfigFile, str)) {
        status = false;
    }

    nm_iam_serializer_string_free(str);
    nm_iam_configuration_free(iamConfig);
    return status;
}
