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

static uint8_t heatpump_state_ = 1;
static int32_t heatpump_room_temperature_ = 19;
static int32_t heatpump_target_temperature_ = 23;
static uint32_t heatpump_mode_ = HPM_HEAT;

struct heatpump_application_state {
    enum heatpump_power_state powerState;
    double heatpump_room_temperature;
    double heatpump_target_temperature;
    enum heatpump_mode mode;
};

struct heatpump_application_state* heatpump_application_state_new();
void heatpump_application_state_free(struct heatpump_application_state* state);

#endif
