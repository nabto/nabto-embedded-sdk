#include "thermostat_state.h"

bool thermostat_state_get_power(struct thermostat_state* state) {
    return state->get_power(state->impl);
}

void thermostat_state_set_power(struct thermostat_state* state, bool power)
{
    state->set_power(state->impl, power);
}

double thermostat_state_get_target(struct thermostat_state* state) {
    return state->get_target(state->impl);
}

void thermostat_state_set_target(struct thermostat_state* state, double target)
{
    state->set_target(state->impl, target);
}

double thermostat_state_get_temperature(struct thermostat_state* state)
{
    return state->get_temperature(state->impl);
}

void thermostat_state_set_mode(struct thermostat_state* state, enum thermostat_mode mode)
{
    state->set_mode(state->impl, mode);
}

enum thermostat_mode thermostat_state_get_mode(struct thermostat_state* state)
{
    return state->get_mode(state->impl);
}

const char* thermostat_state_mode_as_string(enum thermostat_mode mode)
{
    switch (mode) {
        case THERMOSTAT_MODE_COOL: return "COOL";
        case THERMOSTAT_MODE_HEAT: return "HEAT";
        case THERMOSTAT_MODE_DRY: return "DRY";
        case THERMOSTAT_MODE_FAN: return "FAN";
    }
    return "UNKNOWN";
}
