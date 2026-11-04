#include "thermostat_state_data.h"

static const char* LOGM = "thermostat";

static cJSON* encode_schedule_entry_as_json(struct thermostat_schedule_entry* entry)
{
    cJSON* json = cJSON_CreateObject();
    cJSON_AddItemToObject(json, "Target", cJSON_CreateNumber(entry->target));
    cJSON_AddItemToObject(json, "Time", cJSON_CreateString(entry->time));
    cJSON_AddItemToObject(json, "Enabled", cJSON_CreateBool(entry->enabled));
    return json;
}

cJSON* thermostat_state_data_encode_as_json(struct thermostat_state_data* data)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "Version", 4);

    cJSON* thermostat = cJSON_CreateObject();
    cJSON_AddItemToObject(thermostat, "Mode", cJSON_CreateString(thermostat_state_mode_as_string(data->mode)));
    cJSON_AddItemToObject(thermostat, "Power", cJSON_CreateBool(data->power));
    cJSON_AddItemToObject(thermostat, "Target", cJSON_CreateNumber(data->target));
    cJSON_AddItemToObject(thermostat, "Temperature", cJSON_CreateNumber(data->temperature));

    cJSON* schedule = cJSON_CreateObject();
    cJSON_AddItemToObject(schedule, "Day", encode_schedule_entry_as_json(&data->schedule.day));
    cJSON_AddItemToObject(schedule, "Night", encode_schedule_entry_as_json(&data->schedule.night));
    cJSON_AddItemToObject(thermostat, "Schedule", schedule);

    cJSON_AddItemToObject(root, "Thermostat", thermostat);
    return root;
}

static void decode_schedule_entry_from_json(cJSON* json, struct thermostat_schedule_entry* entry)
{
    if (!cJSON_IsObject(json)) {
        return;
    }
    cJSON* target = cJSON_GetObjectItem(json, "Target");
    cJSON* time = cJSON_GetObjectItem(json, "Time");
    cJSON* enabled = cJSON_GetObjectItem(json, "Enabled");

    if (cJSON_IsNumber(target)) {
        entry->target = target->valuedouble;
    }
    if (cJSON_IsString(time) && thermostat_schedule_time_is_valid(time->valuestring)) {
        memcpy(entry->time, time->valuestring, sizeof(entry->time));
    }
    if (cJSON_IsBool(enabled)) {
        entry->enabled = (enabled->type != cJSON_False);
    }
}

bool thermostat_state_data_decode_from_json(cJSON* json, struct thermostat_state_data* state, struct nn_log* logger)
{
    cJSON* version = cJSON_GetObjectItem(json, "Version");
    // version 3 files are accepted, they lack the schedule which then keeps
    // its default values.
    if (!cJSON_IsNumber(version) || (version->valueint != 3 && version->valueint != 4)) {
        NN_LOG_ERROR(logger, LOGM, "The version of the state is not correct, delete it and start over");
        return false;
    }

    cJSON* thermostat = cJSON_GetObjectItem(json, "Thermostat");

    if (cJSON_IsObject(thermostat)) {
        cJSON* mode = cJSON_GetObjectItem(thermostat, "Mode");
        cJSON* power = cJSON_GetObjectItem(thermostat, "Power");
        cJSON* target = cJSON_GetObjectItem(thermostat, "Target");
        cJSON* temp = cJSON_GetObjectItem(thermostat, "Temperature");
        cJSON* schedule = cJSON_GetObjectItem(thermostat, "Schedule");

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

        if (cJSON_IsObject(schedule)) {
            decode_schedule_entry_from_json(cJSON_GetObjectItem(schedule, "Day"), &state->schedule.day);
            decode_schedule_entry_from_json(cJSON_GetObjectItem(schedule, "Night"), &state->schedule.night);
        }
    }
    return true;
}
