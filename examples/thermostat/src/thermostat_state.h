#ifndef _THERMOSTAT_STATE_H_
#define _THERMOSTAT_STATE_H_

// data interface needed by the thermostat coap calls. This can have different
// implementations depending on the platform which the code runs on.

#include "thermostat.h"

enum thermostat_mode {
    THERMOSTAT_MODE_COOL,
    THERMOSTAT_MODE_HEAT,
    THERMOSTAT_MODE_DRY,
    THERMOSTAT_MODE_FAN
};

struct thermostat_state {
    void* impl;
    bool (*get_power)(void* impl);
    void (*set_power)(void* impl, bool power);
    double (*get_target)(void* impl);
    void (*set_target)(void* impl, double target);
    double (*get_temperature)(void* impl);
    void (*set_mode)(void* impl, enum thermostat_mode mode);
    enum thermostat_mode (*get_mode)(void* impl);
};

const char* thermostat_state_mode_as_string(enum thermostat_mode mode);
const char* thermostat_state_power_as_string(bool power);

bool thermostat_state_get_power(struct thermostat_state* state);

void thermostat_state_set_power(struct thermostat_state* state, bool power);

double thermostat_state_get_target(struct thermostat_state* state);

void thermostat_state_set_target(struct thermostat_state* state, double target);

double thermostat_state_get_temperature(struct thermostat_state* state);

void thermostat_state_set_mode(struct thermostat_state* state, enum thermostat_mode mode);

enum thermostat_mode thermostat_state_get_mode(struct thermostat_state* state);


#endif
