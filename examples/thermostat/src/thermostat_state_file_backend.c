#include "thermostat_state_file_backend.h"

#include <apps/common/json_config.h>

static const char* LOGM = "thermostat";

static bool get_power(void* impl);
static void set_power(void* impl, bool power);
static double get_target(void* impl);
static void set_target(void* impl, double target);
static double get_temperature(void* impl);
static void set_mode(void* impl, enum thermostat_mode mode);
static enum thermostat_mode get_mode(void* impl);

static void save_state(struct thermostat_state_file_backend* fb);

void thermostat_state_file_backend_init(struct thermostat_state_file_backend* fileBackend, struct thermostat_state* thermostatState, struct nm_file* fileImpl, const char* filename)
{
    fileBackend->filename = strdup(filename);
    fileBackend->stateData.mode = THERMOSTAT_MODE_HEAT;
    fileBackend->stateData.temperature = 22.3;
    fileBackend->stateData.target = 22.3;
    fileBackend->stateData.power = false;

    fileBackend->fileImpl = fileImpl;

    thermostatState->impl = fileBackend;
    thermostatState->get_power = get_power;
    thermostatState->set_power = set_power;
    thermostatState->get_target = get_target;
    thermostatState->set_target = set_target;
    thermostatState->get_temperature = get_temperature;
    thermostatState->get_mode = get_mode;
    thermostatState->set_mode = set_mode;
}

void thermostat_state_file_backend_deinit(struct thermostat_state_file_backend* fileBackend)
{
    free(fileBackend->filename);
}

/**
 * Called initially to load state data in from a file
 */
bool thermostate_state_file_backend_load_data(struct thermostat_state_file_backend* fb, struct nn_log* logger)
{
    if (!json_config_exists(fb->fileImpl, fb->filename)) {
        thermostat_state_file_backend_create_default_state_file(fb);
    }
    cJSON* json;
    if (!json_config_load(fb->fileImpl, fb->filename, &json, logger)) {
        NN_LOG_ERROR(logger, LOGM, "Cannot load state from file %s", fb->filename);
        return false;
    }
    bool status = thermostat_state_data_decode_from_json(json, &fb->stateData, logger);
    cJSON_Delete(json);
    return status;
}

bool get_power(void* impl)
{
    struct thermostat_state_file_backend* fb = impl;
    return fb->stateData.power;
}

void set_power(void* impl, bool power)
{
    struct thermostat_state_file_backend* fb = impl;
    fb->stateData.power = power;
    save_state(fb);
}
double get_target(void* impl)
{
    struct thermostat_state_file_backend* fb = impl;
    return fb->stateData.target;

}
void set_target(void* impl, double target)
{
    struct thermostat_state_file_backend* fb = impl;
    fb->stateData.target = target;
    save_state(fb);
}
double get_temperature(void* impl)
{
    struct thermostat_state_file_backend* fb = impl;
    return fb->stateData.temperature;

}
void set_mode(void* impl, enum thermostat_mode mode)
{
    struct thermostat_state_file_backend* fb = impl;
    fb->stateData.mode = mode;
    save_state(fb);
}
enum thermostat_mode get_mode(void* impl)
{
    struct thermostat_state_file_backend* fb = impl;
    return fb->stateData.mode;
}

void print_state(struct thermostat_state_data* stateData)
{
    printf("Thermostat state updated: Target temperature: %.02f, Mode: %s, Power %s\r\n", stateData->target, thermostat_state_mode_as_string(stateData->mode), thermostat_state_power_as_string(stateData->power));
}

void save_state(struct thermostat_state_file_backend* fb)
{
    print_state(&fb->stateData);
    cJSON* j = thermostat_state_data_encode_as_json(&fb->stateData);
    if (j != NULL) {
        json_config_save(fb->fileImpl, fb->filename, j);

        cJSON_Delete(j);
    }
}

void thermostat_state_file_backend_create_default_state_file(struct thermostat_state_file_backend* fb)
{
    fb->stateData.mode = THERMOSTAT_MODE_HEAT;
    fb->stateData.temperature = 22.3;
    fb->stateData.target = 22.3;
    fb->stateData.power = false;
    save_state(fb);
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

void thermostat_state_file_backend_update(struct thermostat_state_file_backend* fb, double deltaTime) {
    if (fb->stateData.power) {
        // Move temperature smoothly towards target
        // When temperature is within smoothingDistance units of target
        // the temperature will start to move more slowly the closer it gets to target
        double speed = 5 * deltaTime;
        double smoothingDistance = 20.0;

        double start = fb->stateData.temperature;
        double end = fb->stateData.target;
        double signedDistance = end - start;
        double distance = (signedDistance > 0) ? signedDistance : -signedDistance;
        double sign = (signedDistance >= 0) ? 1 : -1;

        fb->stateData.temperature += sign * speed * smoothstep(0, smoothingDistance, distance);
    }
}
