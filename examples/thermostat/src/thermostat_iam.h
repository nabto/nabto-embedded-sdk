#ifndef _THERMOSTAT_STATE_H_
#define _THERMOSTAT_STATE_H_

#include <nabto/nabto_device.h>
#include "thermostat.h"
#include <modules/iam/nm_iam_state.h>
#include <nn/log.h>

void thermostat_iam_init(struct thermostat* thermostat);
void thermostat_iam_deinit(struct thermostat* thermostat);

void thermostat_iam_create_default_state(NabtoDevice* device, const char* filename, struct nn_log* logger);

bool thermostat_iam_load_state(struct thermostat* thermostat);

char* thermostat_iam_create_pairing_string(struct thermostat* thermostat, const char* productId, const char* deviceId);

#endif
