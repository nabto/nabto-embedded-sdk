#ifndef _THERMOSTAT_STATE_FILE_BACKEND_H_
#define _THERMOSTAT_STATE_FILE_BACKEND_H_

#include "thermostat_state_data.h"

/**
 * File state backend for the thermostat. This uses the thermostat_state_data
 * for encoding and decoding of the data which is persisted in a file.
 */

struct thermostat_state_file_backend {
    char* filename;
    struct thermostat_state_data stateData;
    struct nm_file* fileImpl;
};

void thermostat_state_file_backend_init(struct thermostat_state_file_backend* fileBackend, struct thermostat_state* thermostatState, struct nm_file* fileImpl, const char* filename);
bool thermostate_state_file_backend_load_data(struct thermostat_state_file_backend* fb, struct nn_log* logger);

void thermostat_state_file_backend_deinit(struct thermostat_state_file_backend* fileBackend);

void thermostat_state_file_backend_create_default_state_file(struct thermostat_state_file_backend* fb);

/**
 * update the temperature in this artificial state backend.
 */
void thermostat_state_file_backend_update(struct thermostat_state_file_backend* fb, double deltaTime);


#endif
