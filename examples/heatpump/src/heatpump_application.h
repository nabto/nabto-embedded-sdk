#ifndef _HEATPUMP_APPLICATION_H_
#define _HEATPUMP_APPLICATION_H_

enum heatpump_mode {
    HEATPUMP_MODE_COOL = 0,
    HEATPUMP_MODE_HEAT = 1,
    HEATPUMP_MODE_CIRCULATE = 2,
    HEATPUMP_MODE_DEHUMIDIFY = 3
};

enum heatpump_power_state {
    HEATPUMP_POWER_STATE_ON,
    HEATPUMP_POWER_STATE_OFF
};

struct heatpump_application_state {
    enum heatpump_power_state powerState;
    double roomTemperature;
    double target;
    enum heatpump_mode mode;
};

struct heatpump_application_state* heatpump_application_state_new();
void heatpump_application_state_free(struct heatpump_application_state* state);


const char* heatpump_power_state_to_string(enum heatpump_power_state powerState);
const char* heatpump_mode_to_string(enum heatpump_mode mode);

#endif
