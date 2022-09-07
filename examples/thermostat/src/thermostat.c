#include "thermostat.h"

#include "thermostat_coap_handler.h"
#include "thermostat_iam.h"

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

static NabtoDeviceError thermostat_init_coap_handlers(struct thermostat* thermostat);

static void save_thermostat_state(const char* filename, const struct thermostat_state* state);

static bool load_thermostat_state(const char* filename, struct thermostat_state* state, struct nn_log* logger);
static void create_default_thermostat_state_file(const char* filename);
static void initFilePaths(struct thermostat* thermostat, const char* homeDir);

// Initialize the thermostat
void thermostat_init(struct thermostat* thermostat, NabtoDevice* device, const char* homeDir, struct nn_log* logger)
{
    memset(thermostat, 0, sizeof(struct thermostat));
    thermostat->device = device;
    thermostat->logger = logger;
    initFilePaths(thermostat, homeDir);
    thermostat_iam_init(thermostat);
    thermostat_init_coap_handlers(thermostat);
    load_thermostat_state(thermostat->thermostatStateFile, &thermostat->state, thermostat->logger);
    thermostat_iam_load_state(thermostat);
}

// Deinitialize the thermostat
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
    thermostat_iam_deinit(thermostat);
}

// stop the thermostat
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

void initFilePaths(struct thermostat* thermostat, const char* homeDir)
{
    char buffer[512];
    memset(buffer, 0, 512);

    snprintf(buffer, 511, "%s/config/device.json", homeDir);
    thermostat->deviceConfigFile = strdup(buffer);
    snprintf(buffer, 511, "%s/keys/device.key", homeDir);
    thermostat->deviceKeyFile = strdup(buffer);
    snprintf(buffer, 511, "%s/state/thermostat_device_iam_state.json", homeDir);
    thermostat->iamStateFile = strdup(buffer);
    snprintf(buffer, 511, "%s/state/thermostat_device_state.json", homeDir);
    thermostat->thermostatStateFile = strdup(buffer);
}

bool thermostat_check_access(struct thermostat* thermostat, NabtoDeviceCoapRequest* request, const char* action)
{
    if (!nm_iam_check_access(&thermostat->iam, nabto_device_coap_request_get_connection_ref(request), action, NULL)) {
        return false;
    }
    return true;
}

void thermostat_reinit_state(struct thermostat* thermostat)
{
    thermostat_iam_create_default_state(thermostat->device, thermostat->iamStateFile, thermostat->logger);
    create_default_thermostat_state_file(thermostat->thermostatStateFile);
}

// Functions for handling thermostat state: mode, power, target
void thermostat_set_mode(struct thermostat* thermostat, enum thermostat_mode mode)
{
    thermostat->state.mode = mode;
    save_thermostat_state(thermostat->thermostatStateFile, &thermostat->state);
}
void thermostat_set_target(struct thermostat* thermostat, double target)
{
    thermostat->state.target = target;
    save_thermostat_state(thermostat->thermostatStateFile, &thermostat->state);
}

void thermostat_set_power(struct thermostat* thermostat, bool power)
{
    thermostat->state.power = power;
    save_thermostat_state(thermostat->thermostatStateFile, &thermostat->state);
}

const char* mode_as_string(enum thermostat_mode mode)
{
    switch (mode) {
        case THERMOSTAT_MODE_COOL: return "COOL";
        case THERMOSTAT_MODE_HEAT: return "HEAT";
        case THERMOSTAT_MODE_DRY: return "DRY";
        case THERMOSTAT_MODE_FAN: return "FAN";
    }
    return "UNKNOWN";
}

void save_thermostat_state(const char* filename, const struct thermostat_state* state)
{
    cJSON* root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "Version", 3);

    cJSON* thermostat = cJSON_CreateObject();
    cJSON_AddItemToObject(thermostat, "Mode", cJSON_CreateString(mode_as_string(state->mode)));
    cJSON_AddItemToObject(thermostat, "Power", cJSON_CreateBool(state->power));
    cJSON_AddItemToObject(thermostat, "Target", cJSON_CreateNumber(state->target));
    cJSON_AddItemToObject(thermostat, "Temperature", cJSON_CreateNumber(state->temperature));

    cJSON_AddItemToObject(root, "Thermostat", thermostat);

    json_config_save(filename, root);

    cJSON_Delete(root);
}

bool load_thermostat_state(const char* filename, struct thermostat_state* state, struct nn_log* logger)
{
    if (!json_config_exists(filename)) {
        create_default_thermostat_state_file(filename);
    }
    cJSON* json;
    if (!json_config_load(filename, &json, logger)) {
        NN_LOG_ERROR(logger, LOGM, "Cannot load state from file %s", filename);
        return false;
    }

    cJSON* version = cJSON_GetObjectItem(json, "Version");
    if (!cJSON_IsNumber(version) || version->valueint != 3) {
        NN_LOG_ERROR(logger, LOGM, "The version of the state file %s is not correct, delete it and start over", filename);
        return false;
    }

    cJSON* thermostat = cJSON_GetObjectItem(json, "Thermostat");

    if (cJSON_IsObject(thermostat)) {
        cJSON* mode = cJSON_GetObjectItem(thermostat, "Mode");
        cJSON* power = cJSON_GetObjectItem(thermostat, "Power");
        cJSON* target = cJSON_GetObjectItem(thermostat, "Target");
        cJSON* temp = cJSON_GetObjectItem(thermostat, "Temperature");

        if (cJSON_IsString(mode)) {
            if (strcmp(mode->valuestring, "COOL") == 0) {
                state->mode = THERMOSTAT_MODE_COOL;
            } else  if (strcmp(mode->valuestring, "HEAT") == 0) {
                state->mode = THERMOSTAT_MODE_HEAT;
            } else  if (strcmp(mode->valuestring, "DRY") == 0) {
                state->mode = THERMOSTAT_MODE_DRY;
            } else  if (strcmp(mode->valuestring, "FAN") == 0) {
                state->mode = THERMOSTAT_MODE_FAN;
            } else {
                return false;
            }
        }

        if (cJSON_IsNumber(target)) {
            state->target = target->valuedouble;
        }

        if (cJSON_IsNumber(temp)) {
            state->temperature = temp->valuedouble;
        }

        if (cJSON_IsBool(power)) {
            if (power->type == cJSON_False) {
                state->power = false;
            } else {
                state->power = true;
            }
        }
    }

    cJSON_Delete(json);
    return true;

}

void create_default_thermostat_state_file(const char* filename)
{
    struct thermostat_state state;
    state.mode = THERMOSTAT_MODE_HEAT;
    state.temperature = 22.3;
    state.target = state.temperature;
    state.power = false;
    save_thermostat_state(filename, &state);
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
