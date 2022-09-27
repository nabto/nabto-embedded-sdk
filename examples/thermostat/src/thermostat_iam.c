
#include <apps/common/string_file.h>
#include <apps/common/json_config.h>
#include <apps/common/random_string.h>


#include "thermostat_iam.h"

#include <modules/iam/nm_iam_serializer.h>

#include <cjson/cJSON.h>

#define LOGM "thermostat_iam"

static void thermostat_iam_state_changed(struct nm_iam* iam, void* userData);
static bool load_iam_config(struct thermostat* thermostat);
static void save_iam_state(const char* filename, struct nm_iam_state* state, struct nn_log* logger);


void thermostat_iam_init(struct thermostat* thermostat)
{
    nm_iam_init(&thermostat->iam, thermostat->device, thermostat->logger);
    load_iam_config(thermostat);
    nm_iam_set_state_changed_callback(&thermostat->iam, thermostat_iam_state_changed, thermostat);

}

void thermostat_iam_deinit(struct thermostat* thermostat)
{
    nm_iam_deinit(&thermostat->iam);
}

void thermostat_iam_state_changed(struct nm_iam* iam, void* userData)
{
    (void)iam;
    struct thermostat* thermostat = userData;
    struct nm_iam_state* state = nm_iam_dump_state(&thermostat->iam);
    if (state == NULL) {
        return;
    } else {
        save_iam_state(thermostat->iamStateFile, state, thermostat->logger);
        nm_iam_state_free(state);
    }
}

void save_iam_state(const char* filename, struct nm_iam_state* state, struct nn_log* logger)
{
    (void)logger;
    char* str = NULL;
    if (!nm_iam_serializer_state_dump_json(state, &str)) {
    } else if (!string_file_save(filename, str)) {
    }
    nm_iam_serializer_string_free(str);
}

void thermostat_iam_create_default_state(NabtoDevice* device, const char* filename, struct nn_log* logger)
{
    struct nm_iam_state* state = nm_iam_state_new();
    nm_iam_state_set_open_pairing_role(state, "Administrator");
    nm_iam_state_set_friendly_name(state, "Thermostat");
    nm_iam_state_set_local_initial_pairing(state, false);
    nm_iam_state_set_local_open_pairing(state, true);
    nm_iam_state_set_password_open_password(state, random_password(12));
    nm_iam_state_set_password_open_pairing(state, true);
    char* sct = NULL;
    nabto_device_create_server_connect_token(device, &sct);
    nm_iam_state_set_password_open_sct(state, sct);
    nabto_device_string_free(sct);
    save_iam_state(filename, state, logger);
    nm_iam_state_free(state);
}

bool thermostat_iam_load_state(struct thermostat* thermostat)
{
    if (!string_file_exists(thermostat->iamStateFile)) {
        thermostat_iam_create_default_state(thermostat->device, thermostat->iamStateFile, thermostat->logger);
    }

    bool status = true;
    char* str = NULL;
    if (!string_file_load(thermostat->iamStateFile, &str)) {
        NN_LOG_INFO(thermostat->logger, LOGM, "IAM state file (%s) does not exist, creating new default state. ", thermostat->iamStateFile);
        thermostat_iam_create_default_state(thermostat->device, thermostat->iamStateFile, thermostat->logger);
        if (!string_file_load(thermostat->iamStateFile, &str)) {
            NN_LOG_ERROR(thermostat->logger, LOGM, "Load IAM state file (%s) failed. Ensure the file is available for read/write. ", thermostat->iamStateFile);
            return false;
        }
    }
    struct nm_iam_state* is = nm_iam_state_new();
    if (!nm_iam_serializer_state_load_json(is, str, thermostat->logger)) {
         NN_LOG_ERROR(thermostat->logger, LOGM, "Loading state failed, try to delete %s to make a new default file", thermostat->iamStateFile);
        free(str);
        return false;
    }

    if (is->friendlyName == NULL) {
        NN_LOG_INFO(
            thermostat->logger, LOGM,
            "No IAM friendly name in state. Adding default: Thermostat");
        nm_iam_state_set_friendly_name(is, "Thermostat");
        save_iam_state(thermostat->iamStateFile, is, thermostat->logger);
    }

    if (!nm_iam_load_state(&thermostat->iam, is)) {
        NN_LOG_ERROR(thermostat->logger, LOGM, "Failed to load state into IAM module");
        nm_iam_state_free(is);
        is = NULL;
        status = false;
    }
    free(str);
    return status;
}


bool load_iam_config(struct thermostat* thermostat)
{
    struct nm_iam_configuration* conf = nm_iam_configuration_new();
    {
        // Policy allowing pairing
        struct nm_iam_policy* p = nm_iam_configuration_policy_new("Pairing");
        struct nm_iam_statement* s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(s, "IAM:GetPairing");
        nm_iam_configuration_statement_add_action(s, "IAM:PairingPasswordOpen");
        nm_iam_configuration_statement_add_action(s, "IAM:PairingPasswordInvite");
        nm_iam_configuration_statement_add_action(s, "IAM:PairingLocalInitial");
        nm_iam_configuration_statement_add_action(s, "IAM:PairingLocalOpen");
        nm_iam_configuration_add_policy(conf, p);
    }
    {
        // Policy allowing control of the thermostat
        struct nm_iam_policy* p = nm_iam_configuration_policy_new("ThermostatControl");
        struct nm_iam_statement* s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(s, "Thermostat:Get");
        nm_iam_configuration_statement_add_action(s, "Thermostat:Set");
        nm_iam_configuration_add_policy(conf, p);
    }
    {
        // Policy allowing management of IAM state
        struct nm_iam_policy* p = nm_iam_configuration_policy_new("ManageIam");
        struct nm_iam_statement* s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(s, "IAM:ListUsers");
        nm_iam_configuration_statement_add_action(s, "IAM:GetUser");
        nm_iam_configuration_statement_add_action(s, "IAM:DeleteUser");
        nm_iam_configuration_statement_add_action(s, "IAM:SetUserRole");
        nm_iam_configuration_statement_add_action(s, "IAM:ListRoles");
        nm_iam_configuration_statement_add_action(s, "IAM:SetSettings");
        nm_iam_configuration_statement_add_action(s, "IAM:GetSettings");
        nm_iam_configuration_statement_add_action(s, "IAM:SetDeviceInfo");

        nm_iam_configuration_add_policy(conf, p);
    }

    {
        // Policy allowing management of own IAM user
        struct nm_iam_policy* p = nm_iam_configuration_policy_new("ManageOwnUser");
        {
            struct nm_iam_statement* s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
            nm_iam_configuration_statement_add_action(s, "IAM:GetUser");
            nm_iam_configuration_statement_add_action(s, "IAM:DeleteUser");
            nm_iam_configuration_statement_add_action(s, "IAM:SetUserDisplayName");

            // Create a condition such that only connections where the
            // UserId matches the UserId of the operation is allowed. E.g. IAM:Username == ${Connection:Username}

            struct nm_iam_condition* c = nm_iam_configuration_statement_create_condition(s, NM_IAM_CONDITION_OPERATOR_STRING_EQUALS, "IAM:Username");
            nm_iam_configuration_condition_add_value(c, "${Connection:Username}");
        }
        {
            struct nm_iam_statement* s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
            nm_iam_configuration_statement_add_action(s, "IAM:ListUsers");
            nm_iam_configuration_statement_add_action(s, "IAM:ListRoles");
        }

        nm_iam_configuration_add_policy(conf, p);
    }

    {
        // Role allowing unpaired connections to pair
        struct nm_iam_role* r = nm_iam_configuration_role_new("Unpaired");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_add_role(conf,r);
    }
    {
        // Role allowing everything assigned to administrators
        struct nm_iam_role* r = nm_iam_configuration_role_new("Administrator");
        nm_iam_configuration_role_add_policy(r, "ManageOwnUser");
        nm_iam_configuration_role_add_policy(r, "ManageIam");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_role_add_policy(r, "ThermostatControl");
        nm_iam_configuration_add_role(conf, r);
    }

    // Connections which does not have a paired user in the system gets the Unpaired role.
    nm_iam_configuration_set_unpaired_role(conf, "Unpaired");

    return nm_iam_load_configuration(&thermostat->iam, conf);
}


char* thermostat_iam_create_pairing_string(struct thermostat* thermostat, const char* productId, const char* deviceId)
{
    struct nm_iam_state* state = nm_iam_dump_state(&thermostat->iam);
    if (state == NULL) {
        return NULL;
    }

    char* pairStr = (char*)calloc(1, 512);
    if (pairStr == NULL) {
        nm_iam_state_free(state);
        return NULL;
    }

    snprintf(pairStr, 511, "p=%s,d=%s,pwd=%s,sct=%s", productId, deviceId,
             state->passwordOpenPassword, state->passwordOpenSct);

    nm_iam_state_free(state);
    return pairStr;
}
