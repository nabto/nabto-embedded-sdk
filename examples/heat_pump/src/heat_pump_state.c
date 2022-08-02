
#include <apps/common/string_file.h>
#include <apps/common/json_config.h>
#include <apps/common/random_string.h>


#include "heat_pump_state.h"


#include <modules/iam/nm_iam_serializer.h>

#include <cjson/cJSON.h>

#define LOGM "heat_pump_state"

void save_iam_state(const char* filename, struct nm_iam_state* state, struct nn_log* logger)
{
    (void)logger;
    char* str = NULL;
    if (!nm_iam_serializer_state_dump_json(state, &str)) {
    } else if (!string_file_save(filename, str)) {
    }
    nm_iam_serializer_string_free(str);
}

const char* mode_as_string(enum heat_pump_mode mode) {
    switch (mode) {
        case HEAT_PUMP_MODE_COOL: return "COOL";
        case HEAT_PUMP_MODE_HEAT: return "HEAT";
        case HEAT_PUMP_MODE_DRY: return "DRY";
        case HEAT_PUMP_MODE_FAN: return "FAN";
    }
    return "UNKNOWN";
}

void save_heat_pump_state(const char* filename, const struct heat_pump_state* state)
{
    cJSON* root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "Version", 3);

    cJSON* heatPump = cJSON_CreateObject();
    cJSON_AddItemToObject(heatPump, "Mode", cJSON_CreateString(mode_as_string(state->mode)));
    cJSON_AddItemToObject(heatPump, "Power", cJSON_CreateBool(state->power));
    cJSON_AddItemToObject(heatPump, "Target", cJSON_CreateNumber(state->target));
    cJSON_AddItemToObject(heatPump, "Temperature", cJSON_CreateNumber(state->temperature));

    cJSON_AddItemToObject(root, "HeatPump", heatPump);

    json_config_save(filename, root);

    cJSON_Delete(root);
}

bool load_heat_pump_state(const char* filename, struct heat_pump_state* state, struct nn_log* logger)
{
    if (!json_config_exists(filename)) {
        create_default_heat_pump_state(filename);
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

    cJSON* heatPump = cJSON_GetObjectItem(json, "HeatPump");

    if (cJSON_IsObject(heatPump)) {
        cJSON* mode = cJSON_GetObjectItem(heatPump, "Mode");
        cJSON* power = cJSON_GetObjectItem(heatPump, "Power");
        cJSON* target = cJSON_GetObjectItem(heatPump, "Target");
        cJSON* temp = cJSON_GetObjectItem(heatPump, "Temperature");

        if (cJSON_IsString(mode)) {
            if (strcmp(mode->valuestring, "COOL") == 0) {
                state->mode = HEAT_PUMP_MODE_COOL;
            } else  if (strcmp(mode->valuestring, "HEAT") == 0) {
                state->mode = HEAT_PUMP_MODE_HEAT;
            } else  if (strcmp(mode->valuestring, "DRY") == 0) {
                state->mode = HEAT_PUMP_MODE_DRY;
            } else  if (strcmp(mode->valuestring, "FAN") == 0) {
                state->mode = HEAT_PUMP_MODE_FAN;
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

void create_default_iam_state(NabtoDevice* device, const char* filename, struct nn_log* logger)
{
    struct nm_iam_state* state = nm_iam_state_new();
    struct nm_iam_user* user = nm_iam_state_user_new("admin");
    // TODO create sct
    char* sct = NULL;
    nabto_device_create_server_connect_token(device, &sct);
    nm_iam_state_user_set_sct(user, sct);
    nabto_device_string_free(sct);
    nm_iam_state_user_set_role(user, "Administrator");
    nm_iam_state_add_user(state, user);
    nm_iam_state_set_initial_pairing_username(state, "admin");
    nm_iam_state_set_local_initial_pairing(state, true);
    nm_iam_state_set_local_open_pairing(state, true);
    nm_iam_state_set_open_pairing_role(state, "Standard");
    nm_iam_state_set_password_open_password(state, random_password(12));
    nm_iam_state_set_password_open_pairing(state, true);
    save_iam_state(filename, state, logger);
    nm_iam_state_free(state);
}
void create_default_heat_pump_state(const char* filename)
{
    struct heat_pump_state state;
    state.mode = HEAT_PUMP_MODE_HEAT;
    state.temperature = 22.3;
    state.target = state.temperature;
    state.power = false;
    save_heat_pump_state(filename, &state);
}
