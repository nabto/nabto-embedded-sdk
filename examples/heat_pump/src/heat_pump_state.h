#ifndef _THERMOSTAT_STATE_H_
#define _THERMOSTAT_STATE_H_

#include <nabto/nabto_device.h>
#include <modules/iam/nm_iam_state.h>
#include <nn/log.h>

enum thermostat_mode {
    THERMOSTAT_MODE_COOL,
    THERMOSTAT_MODE_HEAT,
    THERMOSTAT_MODE_DRY,
    THERMOSTAT_MODE_FAN
};

struct thermostat_state {
    bool power;
    double target;
    double temperature;
    enum thermostat_mode mode;
};

const char* mode_as_string(enum thermostat_mode mode);

void save_iam_state(const char* filename, struct nm_iam_state* state, struct nn_log* logger);
void save_thermostat_state(const char* filename, const struct thermostat_state* state);

bool load_thermostat_state(const char* filename, struct thermostat_state* state, struct nn_log* logger);

void create_default_iam_state(NabtoDevice* device, const char* filename, struct nn_log* logger);
void create_default_thermostat_state(const char* filename);

#endif
