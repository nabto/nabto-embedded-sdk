#include "thermostat_file.h"
#include "thermostat.h"
#include <apps/common/json_config.h>
#include <cjson/cJSON.h>

#include "string.h"

void thermostat_file_deinit(struct thermostat_file* tf)
{
    free(tf->thermostatStateFile);
    free(tf->iamStateFile);
    free(tf->deviceKeyFile);
    free(tf->deviceConfigFile);
}

void thermostat_file_init(struct thermostat_file* tf, const char* homeDir)
{
    char buffer[512];
    memset(buffer, 0, 512);

    snprintf(buffer, 511, "%s/config/device.json", homeDir);
    tf->deviceConfigFile = strdup(buffer);
    snprintf(buffer, 511, "%s/keys/device.key", homeDir);
    tf->deviceKeyFile = strdup(buffer);
    snprintf(buffer, 511, "%s/state/thermostat_device_iam_state.json", homeDir);
    tf->iamStateFile = strdup(buffer);
    snprintf(buffer, 511, "%s/state/thermostat_device_state.json", homeDir);
    tf->thermostatStateFile = strdup(buffer);
}


// void save_thermostat_state(const char* filename, const struct thermostat_state* state)
// {
//     cJSON* root = cJSON_CreateObject();

//     cJSON_AddNumberToObject(root, "Version", 3);

//     cJSON* thermostat = cJSON_CreateObject();
//     cJSON_AddItemToObject(thermostat, "Mode", cJSON_CreateString(mode_as_string(thermostat_state_get_mode(state))));
//     cJSON_AddItemToObject(thermostat, "Power", cJSON_CreateBool(thermostat_state_get_power(state)));
//     cJSON_AddItemToObject(thermostat, "Target", cJSON_CreateNumber(thermostat_stateg_get_target(state)));
//     cJSON_AddItemToObject(thermostat, "Temperature", cJSON_CreateNumber(thermostat_state_get_temperature(state)));

//     cJSON_AddItemToObject(root, "Thermostat", thermostat);

//     json_config_save(filename, root);

//     cJSON_Delete(root);
// }

// bool load_thermostat_state(const char* filename, struct thermostat_state* state, struct nn_log* logger)
// {
//     if (!json_config_exists(filename)) {
//         create_default_thermostat_state_file(filename);
//     }
//     cJSON* json;
//     if (!json_config_load(filename, &json, logger)) {
//         NN_LOG_ERROR(logger, LOGM, "Cannot load state from file %s", filename);
//         return false;
//     }

//     cJSON* version = cJSON_GetObjectItem(json, "Version");
//     if (!cJSON_IsNumber(version) || version->valueint != 3) {
//         NN_LOG_ERROR(logger, LOGM, "The version of the state file %s is not correct, delete it and start over", filename);
//         return false;
//     }

//     cJSON* thermostat = cJSON_GetObjectItem(json, "Thermostat");

//     if (cJSON_IsObject(thermostat)) {
//         cJSON* mode = cJSON_GetObjectItem(thermostat, "Mode");
//         cJSON* power = cJSON_GetObjectItem(thermostat, "Power");
//         cJSON* target = cJSON_GetObjectItem(thermostat, "Target");
//         cJSON* temp = cJSON_GetObjectItem(thermostat, "Temperature");

//         if (cJSON_IsString(mode)) {
//             if (strcmp(mode->valuestring, "COOL") == 0) {
//                 state->mode = THERMOSTAT_MODE_COOL;
//             } else  if (strcmp(mode->valuestring, "HEAT") == 0) {
//                 state->mode = THERMOSTAT_MODE_HEAT;
//             } else  if (strcmp(mode->valuestring, "DRY") == 0) {
//                 state->mode = THERMOSTAT_MODE_DRY;
//             } else  if (strcmp(mode->valuestring, "FAN") == 0) {
//                 state->mode = THERMOSTAT_MODE_FAN;
//             } else {
//                 return false;
//             }
//         }

//         if (cJSON_IsNumber(target)) {
//             state->target = target->valuedouble;
//         }

//         if (cJSON_IsNumber(temp)) {
//             state->temperature = temp->valuedouble;
//         }

//         if (cJSON_IsBool(power)) {
//             if (power->type == cJSON_False) {
//                 state->power = false;
//             } else {
//                 state->power = true;
//             }
//         }
//     }

//     cJSON_Delete(json);
//     return true;

// }


// void create_default_thermostat_state_file(const char* filename)
// {
//     struct thermostat_state state;
//     state.mode = THERMOSTAT_MODE_HEAT;
//     state.temperature = 22.3;
//     state.target = state.temperature;
//     state.power = false;
//     save_thermostat_state(filename, &state);
// }
