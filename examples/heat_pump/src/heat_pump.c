#include "heat_pump.h"

#include "heat_pump_coap_handler.h"
#include "heat_pump_state.h"

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

static const char* LOGM = "heat_pump";

static bool load_iam_policy(struct heat_pump* heatPump);
static bool load_iam_state(struct heat_pump* heatPump);

static void heat_pump_state_changed(struct nm_iam* iam, void* userData);
static NabtoDeviceError heat_pump_init_coap_handlers(struct heat_pump* heatPump);

void heat_pump_init(struct heat_pump* heatPump, NabtoDevice* device, struct nn_log* logger)
{
    memset(heatPump, 0, sizeof(struct heat_pump));
    heatPump->device = device;
    heatPump->logger = logger;

    nm_iam_init(&heatPump->iam, heatPump->device, heatPump->logger);
    load_iam_policy(heatPump);
    nm_iam_set_state_changed_callback(&heatPump->iam, heat_pump_state_changed, heatPump);
    heat_pump_init_coap_handlers(heatPump);
}

void heat_pump_deinit(struct heat_pump* heatPump)
{
    free(heatPump->heatPumpStateFile);
    free(heatPump->iamStateFile);
    free(heatPump->deviceKeyFile);
    free(heatPump->deviceConfigFile);
    heat_pump_coap_handler_deinit(&heatPump->coapGet);
    heat_pump_coap_handler_deinit(&heatPump->coapSetMode);
    heat_pump_coap_handler_deinit(&heatPump->coapSetPower);
    heat_pump_coap_handler_deinit(&heatPump->coapSetTarget);
    nm_iam_deinit(&heatPump->iam);
}

void heat_pump_start(struct heat_pump* heatPump) {
    // these needs to be called after init since the filenames are not ready yet in init.
    load_heat_pump_state(heatPump->heatPumpStateFile, &heatPump->state, heatPump->logger);
    load_iam_state(heatPump);
}

void heat_pump_stop(struct heat_pump* heatPump)
{
    nm_iam_stop(&heatPump->iam);
    heat_pump_coap_handler_stop(&heatPump->coapGet);
    heat_pump_coap_handler_stop(&heatPump->coapSetMode);
    heat_pump_coap_handler_stop(&heatPump->coapSetPower);
    heat_pump_coap_handler_stop(&heatPump->coapSetTarget);
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

void heat_pump_update(struct heat_pump* heatPump, double deltaTime) {
    if (heatPump->state.power) {
        // Move temperature smoothly towards target
        // When temperature is within smoothingDistance units of target
        // the temperature will start to move more slowly the closer it gets to target
        double speed = 5 * deltaTime;
        double smoothingDistance = 20.0;

        double start = heatPump->state.temperature;
        double end = heatPump->state.target;
        double signedDistance = end - start;
        double distance = (signedDistance > 0) ? signedDistance : -signedDistance;
        double sign = signedDistance / distance;

        heatPump->state.temperature += sign * speed * smoothstep(0, smoothingDistance, distance);
    }
}

void heat_pump_state_changed(struct nm_iam* iam, void* userData)
{
    (void)iam;
    struct heat_pump* heatPump = userData;
    struct nm_iam_state* state = nm_iam_dump_state(&heatPump->iam);
    if (state == NULL) {
        return;
    } else {
        char* str = NULL;
        if (!nm_iam_serializer_state_dump_json(state, &str)) {
        } else if (!string_file_save(heatPump->iamStateFile, str)) {
        }
        nm_iam_serializer_string_free(str);
        nm_iam_state_free(state);
    }
}

bool load_iam_state(struct heat_pump* heatPump)
{
    if (!string_file_exists(heatPump->iamStateFile)) {
        create_default_iam_state(heatPump->device, heatPump->iamStateFile, heatPump->logger);
    }

    bool status = true;
    char* str = NULL;
    if (!string_file_load(heatPump->iamStateFile, &str)) {
        NN_LOG_INFO(heatPump->logger, LOGM, "IAM state file (%s) does not exist, creating new default state. ", heatPump->iamStateFile);
        create_default_iam_state(heatPump->device, heatPump->iamStateFile, heatPump->logger);
        if (!string_file_load(heatPump->iamStateFile, &str)) {
            NN_LOG_ERROR(heatPump->logger, LOGM, "Load IAM state file (%s) failed. Ensure the file is available for read/write. ", heatPump->iamStateFile);
            return false;
        }
    }
    struct nm_iam_state* is = nm_iam_state_new();
    nm_iam_serializer_state_load_json(is, str, heatPump->logger);
    if (!nm_iam_load_state(&heatPump->iam, is)) {
        NN_LOG_ERROR(heatPump->logger, LOGM, "Failed to load state into IAM module");
        nm_iam_state_free(is);
        is = NULL;
        status = false;
    }
    free(str);
    return status;
}

void heat_pump_save_state(struct heat_pump* heatPump)
{
    save_heat_pump_state(heatPump->heatPumpStateFile, &heatPump->state);
}

NabtoDeviceError heat_pump_init_coap_handlers(struct heat_pump* heatPump)
{
    NabtoDeviceError ec;
    ec = heat_pump_get_init(&heatPump->coapGet, heatPump->device, heatPump);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = heat_pump_set_mode_init(&heatPump->coapSetMode, heatPump->device, heatPump);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = heat_pump_set_power_init(&heatPump->coapSetPower, heatPump->device, heatPump);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    ec = heat_pump_set_target_init(&heatPump->coapSetTarget, heatPump->device, heatPump);
    if (ec != NABTO_DEVICE_EC_OK) {
        return ec;
    }
    return NABTO_DEVICE_EC_OK;
}

void heat_pump_set_mode(struct heat_pump* heatPump, enum heat_pump_mode mode)
{
    heatPump->state.mode = mode;
    heat_pump_save_state(heatPump);
}
void heat_pump_set_target(struct heat_pump* heatPump, double target)
{
    heatPump->state.target = target;
    heat_pump_save_state(heatPump);
}

void heat_pump_set_power(struct heat_pump* heatPump, bool power)
{
    heatPump->state.power = power;
    heat_pump_save_state(heatPump);
}

bool heat_pump_check_access(struct heat_pump* heatPump, NabtoDeviceCoapRequest* request, const char* action)
{
    if (!nm_iam_check_access(&heatPump->iam, nabto_device_coap_request_get_connection_ref(request), action, NULL)) {
        return false;
    }
    return true;
}

bool load_iam_policy(struct heat_pump* heatPump)
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
        struct nm_iam_policy* p = nm_iam_configuration_policy_new("HeatPumpControl");
        struct nm_iam_statement* s = nm_iam_configuration_policy_create_statement(p, NM_IAM_EFFECT_ALLOW);
        nm_iam_configuration_statement_add_action(s, "HeatPump:Get");
        nm_iam_configuration_statement_add_action(s, "HeatPump:Set");
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
            nm_iam_configuration_statement_add_action(s, "IAM:SetDisplayName");

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
        nm_iam_configuration_role_add_policy(r, "ManageIam");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_role_add_policy(r, "HeatPumpControl");
        nm_iam_configuration_add_role(conf, r);
    }
    {
        struct nm_iam_role* r = nm_iam_configuration_role_new("Standard");
        nm_iam_configuration_role_add_policy(r, "HeatPumpControl");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_role_add_policy(r, "ManageOwnUser");
        nm_iam_configuration_add_role(conf, r);
    }
    {
        //TODO: guest should have access to LocalHeatpumpControl and LocalDeviceInfo
        struct nm_iam_role* r = nm_iam_configuration_role_new("Guest");
        nm_iam_configuration_role_add_policy(r, "ManageOwnUser");
        nm_iam_configuration_role_add_policy(r, "Pairing");
        nm_iam_configuration_add_role(conf, r);
    }

    // Connections which does not have a paired user in the system gets the Unpaired role.
    nm_iam_configuration_set_unpaired_role(conf, "Unpaired");

    return nm_iam_load_configuration(&heatPump->iam, conf);
}

void heat_pump_reinit_state(struct heat_pump* heatPump)
{
    create_default_iam_state(heatPump->device, heatPump->iamStateFile, heatPump->logger);
    create_default_heat_pump_state(heatPump->heatPumpStateFile);
}
