#ifndef THERMOSTAT_STATE_H_
#define THERMOSTAT_STATE_H_

// data interface needed by the thermostat coap calls. This can have different
// implementations depending on the platform which the code runs on.

#include "thermostat.h"

#include <stddef.h>

enum thermostat_mode {
    THERMOSTAT_MODE_COOL,
    THERMOSTAT_MODE_HEAT,
    THERMOSTAT_MODE_DRY,
    THERMOSTAT_MODE_FAN
};

struct thermostat_schedule_entry {
    double target;
    char time[6]; // "HH:MM"
    bool enabled;
};

struct thermostat_schedule {
    struct thermostat_schedule_entry day;
    struct thermostat_schedule_entry night;
};

typedef void (*thermostat_state_changed)(void* userData);

struct thermostat_state {
    void* impl;
    bool (*get_power)(void* impl);
    void (*set_power)(void* impl, bool power);
    double (*get_target)(void* impl);
    void (*set_target)(void* impl, double target);
    double (*get_temperature)(void* impl);
    void (*set_mode)(void* impl, enum thermostat_mode mode);
    enum thermostat_mode (*get_mode)(void* impl);
    void (*get_schedule)(void* impl, struct thermostat_schedule* schedule);
    void (*set_schedule)(void* impl, const struct thermostat_schedule* schedule);
    // observer which is invoked after each state change made through the
    // setters below.
    thermostat_state_changed changedCallback;
    void* changedCallbackUserData;
};

const char* thermostat_state_mode_as_string(enum thermostat_mode mode);
const char* thermostat_state_power_as_string(bool power);

// validate that a time string has the format "HH:MM" with 00-23 hours and
// 00-59 minutes.
bool thermostat_schedule_time_is_valid(const char* time);

bool thermostat_state_get_power(struct thermostat_state* state);

void thermostat_state_set_power(struct thermostat_state* state, bool power);

double thermostat_state_get_target(struct thermostat_state* state);

void thermostat_state_set_target(struct thermostat_state* state, double target);

double thermostat_state_get_temperature(struct thermostat_state* state);

void thermostat_state_set_mode(struct thermostat_state* state, enum thermostat_mode mode);

enum thermostat_mode thermostat_state_get_mode(struct thermostat_state* state);

void thermostat_state_get_schedule(struct thermostat_state* state, struct thermostat_schedule* schedule);

void thermostat_state_set_schedule(struct thermostat_state* state, const struct thermostat_schedule* schedule);

void thermostat_state_set_changed_callback(struct thermostat_state* state, thermostat_state_changed callback, void* userData);

/**
 * Encode the full thermostat state (Mode, Target, Power, Temperature,
 * Schedule) as a CBOR map. NULL buffer returns the needed capacity.
 * With a buffer, returns bytes written, or zero if capacity is insufficient.
 * Use THERMOSTAT_STATE_CBOR_CAPACITY to encode changing state in one pass.
 */
#define THERMOSTAT_STATE_CBOR_CAPACITY 1024
size_t thermostat_state_encode(struct thermostat_state* state, void* buffer, size_t bufferSize);

#endif
