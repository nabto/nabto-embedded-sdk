#ifndef _THERMOSTAT_STATE_DATA_H_
#define _THERMOSTAT_STATE_DATA_H_

#include "thermostat_state.h"

#include <cjson/cJSON.h>

/**
 * This is a hypothetical data backend for a thermostat. In a real world
 * thermostat the data would control the real heatpump.
 */

struct thermostat_state_data {
    bool power;
    double target;
    double temperature;
    enum thermostat_mode mode;
};

cJSON* thermostat_state_data_encode_as_json(struct thermostat_state_data* data);
bool thermostat_state_data_decode_from_json(cJSON* json, struct thermostat_state_data* data, struct nn_log* logger);


#endif
