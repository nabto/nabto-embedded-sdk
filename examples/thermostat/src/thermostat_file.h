#ifndef THERMOSTAT_FILE_H_
#define THERMOSTAT_FILE_H_

#include "stdbool.h"

struct thermostat_state;
struct nn_log;

struct thermostat_file {
    char* thermostatStateFile; // contains the thermostat specific state
    char* iamStateFile; // contains the iam state.
    char* deviceKeyFile;
    char* deviceConfigFile;
};

void thermostat_file_init(struct thermostat_file* tf, const char* homeDir);
void thermostat_file_deinit(struct thermostat_file* tf);


#endif
