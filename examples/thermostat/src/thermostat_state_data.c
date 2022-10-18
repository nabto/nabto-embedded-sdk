#include "thermostat_state_data.h"

static const char* LOGM = "thermostat";

cJSON* thermostat_state_data_encode_as_json(struct thermostat_state_data* data)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "Version", 3);

    cJSON* thermostat = cJSON_CreateObject();
    cJSON_AddItemToObject(thermostat, "Mode", cJSON_CreateString(thermostat_state_mode_as_string(data->mode)));
    cJSON_AddItemToObject(thermostat, "Power", cJSON_CreateBool(data->power));
    cJSON_AddItemToObject(thermostat, "Target", cJSON_CreateNumber(data->target));
    cJSON_AddItemToObject(thermostat, "Temperature", cJSON_CreateNumber(data->temperature));

    cJSON_AddItemToObject(root, "Thermostat", thermostat);
    return root;
}

bool thermostat_state_data_decode_from_json(cJSON* json, struct thermostat_state_data* state, struct nn_log* logger)
{
    cJSON* version = cJSON_GetObjectItem(json, "Version");
    if (!cJSON_IsNumber(version) || version->valueint != 3) {
        NN_LOG_ERROR(logger, LOGM, "The version of the state is not correct, delete it and start over");
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
    return true;
}
