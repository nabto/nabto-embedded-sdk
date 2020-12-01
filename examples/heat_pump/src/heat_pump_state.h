#ifndef _HEAT_PUMP_STATE_H_
#define _HEAT_PUMP_STATE_H_

#include <nabto/nabto_device.h>
#include <modules/iam/nm_iam_state.h>
#include <nn/log.h>

enum heat_pump_mode {
    HEAT_PUMP_MODE_COOL,
    HEAT_PUMP_MODE_HEAT,
    HEAT_PUMP_MODE_DRY,
    HEAT_PUMP_MODE_FAN
};

struct heat_pump_state {
    bool power;
    double target;
    enum heat_pump_mode mode;
};

const char* mode_as_string(enum heat_pump_mode mode);

void save_iam_state(const char* filename, struct nm_iam_state* state, struct nn_log* logger);
void save_heat_pump_state(const char* filename, const struct heat_pump_state* state);

bool load_heat_pump_state(const char* filename, struct heat_pump_state* state, struct nn_log* logger);

void create_default_iam_state(NabtoDevice* device, const char* filename, struct nn_log* logger);
void create_default_heat_pump_state(const char* filename);

#endif
