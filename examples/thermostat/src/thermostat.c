#include "thermostat.h"

#include "thermostat_coap_handler.h"
#include "thermostat_state.h"

#include <apps/common/logging.h>
#include <apps/common/json_config.h>
#include <apps/common/string_file.h>

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_serializer.h>
#include <modules/iam/nm_iam_configuration.h>
#include <modules/iam/nm_iam_state.h>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <cjson/cJSON.h>

static const char* LOGM = "thermostat";

static bool load_iam_policy(struct thermostat* thermostat);
static bool load_iam_state(struct thermostat* thermostat);

static void thermostat_state_changed(struct nm_iam* iam, void* userData);
static NabtoDeviceError thermostat_init_coap_handlers(struct thermostat* thermostat);

void thermostat_init(struct thermostat* thermostat, NabtoDevice* device, struct nn_log* logger)
{
    memset(thermostat, 0, sizeof(struct thermostat));
    thermostat->device = device;
    thermostat->logger = logger;

    nm_iam_init(&thermostat->iam, thermostat->device, thermostat->logger);
    load_iam_policy(thermostat);
    nm_iam_set_state_changed_callback(&thermostat->iam, thermostat_state_changed, thermostat);
    thermostat_init_coap_handlers(thermostat);
}

void thermostat_deinit(struct thermostat* thermostat)
{
    free(thermostat->thermostatStateFile);
    free(thermostat->iamStateFile);
    free(thermostat->deviceKeyFile);
    free(thermostat->deviceConfigFile);
    thermostat_coap_handler_deinit(&thermostat->coapGet);
    thermostat_coap_handler_deinit(&thermostat->coapSetMode);
    thermostat_coap_handler_deinit(&thermostat->coapSetPower);
    thermostat_coap_handler_deinit(&thermostat->coapSetTarget);

    thermostat_coap_handler_deinit(&thermostat->coapGetLegacy);
    thermostat_coap_handler_deinit(&thermostat->coapSetModeLegacy);
    thermostat_coap_handler_deinit(&thermostat->coapSetPowerLegacy);
    thermostat_coap_handler_deinit(&thermostat->coapSetTargetLegacy);

    nm_iam_deinit(&thermostat->iam);
}

void thermostat_start(struct thermostat* thermostat) {
    // these needs to be called after init since the filenames are not ready yet in init.
    load_thermostat_state(thermostat->thermostatStateFile, &thermostat->state, thermostat->logger);
    load_iam_state(thermostat);
}

void thermostat_stop(struct thermostat* thermostat)
{
    nm_iam_stop(&thermostat->iam);
    thermostat_coap_handler_stop(&thermostat->coapGet);
    thermostat_coap_handler_stop(&thermostat->coapSetMode);
    thermostat_coap_handler_stop(&thermostat->coapSetPower);
    thermostat_coap_handler_stop(&thermostat->coapSetTarget);

    thermostat_coap_handler_stop(&thermostat->coapGetLegacy);
    thermostat_coap_handler_stop(&thermostat->coapSetModeLegacy);
    thermostat_coap_handler_stop(&thermostat->coapSetPowerLegacy);
    thermostat_coap_handler_stop(&thermostat->coapSetTargetLegacy);
}

static double smoothstep(double start, double end, double x)
{
    if (x < start) {
        return 0;
    }

    if (x >= end) {
        return 1;
    }

    x = (x - start) / (end - start);
    return x * x * (3 - 2 * x);
}

void thermostat_update(struct thermostat* thermostat, double deltaTime) {
    if (thermostat->state.power) {
        // Move temperature smoothly towards target
        // When temperature is within smoothingDistance units of target
        // the temperature will start to move more slowly the closer it gets to target
        double speed = 5 * deltaTime;
        double smoothingDistance = 20.0;

        double start = thermostat->state.temperature;
        double end = thermostat->state.target;
        double signedDistance = end - start;
        double distance = (signedDistance > 0) ? signedDistance : -signedDistance;
        double sign = signedDistance / distance;

        thermostat->state.temperature += sign * speed * smoothstep(0, smoothingDistance, distance);
    }
}

void thermostat_state_changed(struct nm_iam* iam, void* userData)
{
    (void)iam;
    struct thermostat* thermostat = userData;
    struct nm_iam_state* state = nm_iam_dump_state(&thermostat->iam);
    if (state == NULL) {
        return;
    } else {
        char* str = NULL;
        if (!nm_iam_serializer_state_dump_json(state, &str)) {
        } else if (!string_file_save(thermostat->iamStateFile, str)) {
        }
        nm_iam_serializer_string_free(str);
        nm_iam_state_free(state);
    }
}

bool load_iam_state(struct thermostat* thermostat)
{
    if (!string_file_exists(thermostat->iamStateFile)) {
        create_default_iam_state(thermostat->device, thermostat->iamStateFile, thermostat->logger);
    }

    bool status = true;
    char* str = NULL;
    if (!string_file_load(thermostat->iamStateFile, &str)) {
        NN_LOG_INFO(thermostat->logger, LOGM, "IAM state file (%s) does not exist, creating new default state. ", thermostat->iamStateFile);
        create_default_iam_state(thermostat->device, thermostat->iamStateFile, thermostat->logger);
        if (!string_file_load(thermostat->iamStateFile, &str)) {
            NN_LOG_ERROR(thermostat->logger, LOGM, "Load IAM state file (%s) failed. Ensure the file is available for read/write. ", thermostat->iamStateFile);
            return false;
        }
    }
    struct nm_iam_state* is = nm_iam_state_new();
    nm_iam_serializer_state_load_json(is, str, thermostat->logger);
    if (!nm_iam_load_state(&thermostat->iam, is)) {
        NN_LOG_ERROR(thermostat->logger, LOGM, "Failed to load state into IAM module");
        nm_iam_state_free(is);
        is = NULL;
        status = false;
    }
    free(str);
    return status;
}

void thermostat_save_state(struct thermostat* thermostat)
{
    save_thermostat_state(thermostat->thermostatStateFile, &thermostat->state);
}

NabtoDeviceError thermostat_init_coap_handlers(struct thermostat* thermostat)
{
    NabtoDeviceError ec;
    ec = thermostat_get_init(&thermostat->coapGet, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_mode_init(&thermostat->coapSetMode, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_power_init(&thermostat->coapSetPower, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_target_init(&thermostat->coapSetTarget, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }

    ec = thermostat_get_legacy_init(&thermostat->coapGetLegacy, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_mode_legacy_init(&thermostat->coapSetModeLegacy, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_power_legacy_init(&thermostat->coapSetPowerLegacy, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = thermostat_set_target_legacy_init(&thermostat->coapSetTargetLegacy, thermostat->device, thermostat);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }

    return NABTO_DEVICE_EC_OK;
}

void thermostat_set_mode(struct thermostat* thermostat, enum thermostat_mode mode)
{
    thermostat->state.mode = mode;
    thermostat_save_state(thermostat);
}
void thermostat_set_target(struct thermostat* thermostat, double target)
{
    thermostat->state.target = target;
    thermostat_save_state(thermostat);
}

void thermostat_set_power(struct thermostat* thermostat, bool power)
{
    thermostat->state.power = power;
    thermostat_save_state(thermostat);
}

bool thermostat_check_access(struct thermostat* thermostat, NabtoDeviceCoapRequest* request, const char* action)
{
    if (!nm_iam_check_access(&thermostat->iam, nabto_device_coap_request_get_connection_ref(request), action, NULL)) {
        return false;
    }
    return true;
}

bool load_iam_policy(struct thermostat* thermostat)
{
    struct nm_iam_configuration* conf = nm_iam_configuration_new();
    {
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
        struct nm_iam_policy* p = nm_iam_configuration_policy_new("ThermostatControl");
        struct nm_iam_statement* s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(s, "Thermostat:Get");
        nm_iam_configuration_statement_add_action(s, "Thermostat:Set");
        nm_iam_configuration_add_policy(conf, p);
    }
    {
        struct nm_iam_policy* p = nm_iam_configuration_policy_new("ManageIam");
        struct nm_iam_statement* s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(s, "IAM:ListUsers");
        nm_iam_configuration_statement_add_action(s, "IAM:GetUser");
        nm_iam_configuration_statement_add_action(s, "IAM:DeleteUser");
        nm_iam_configuration_statement_add_action(s, "IAM:SetUserRole");
        nm_iam_configuration_statement_add_action(s, "IAM:ListRoles");
        nm_iam_configuration_statement_add_action(s, "IAM:SetSettings");
        nm_iam_configuration_statement_add_action(s, "IAM:GetSettings");

        nm_iam_configuration_add_policy(conf, p);
    }

    {
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
        struct nm_iam_role* r = nm_iam_configuration_role_new("Unpaired");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_add_role(conf,r);
    }
    {
        struct nm_iam_role* r = nm_iam_configuration_role_new("Administrator");
        nm_iam_configuration_role_add_policy(r, "ManageOwnUser");
        nm_iam_configuration_role_add_policy(r, "ManageIam");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_role_add_policy(r, "ThermostatControl");
        nm_iam_configuration_add_role(conf, r);
    }
    {
        struct nm_iam_role* r = nm_iam_configuration_role_new("Standard");
        nm_iam_configuration_role_add_policy(r, "ThermostatControl");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_role_add_policy(r, "ManageOwnUser");
        nm_iam_configuration_add_role(conf, r);
    }
    {
        //TODO: guest should have access to LocalThermostatControl and LocalDeviceInfo
        struct nm_iam_role* r = nm_iam_configuration_role_new("Guest");
        nm_iam_configuration_role_add_policy(r, "ManageOwnUser");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_add_role(conf, r);
    }

    // Connections which does not have a paired user in the system gets the Unpaired role.
    nm_iam_configuration_set_unpaired_role(conf, "Unpaired");

    return nm_iam_load_configuration(&thermostat->iam, conf);
}

void thermostat_reinit_state(struct thermostat* thermostat)
{
    create_default_iam_state(thermostat->device, thermostat->iamStateFile, thermostat->logger);
    create_default_thermostat_state(thermostat->thermostatStateFile);
}
