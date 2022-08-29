#ifndef _THERMOSTAT_H_
#define _THERMOSTAT_H_

#include "thermostat_coap_handler.h"
#include "thermostat_state.h"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>



#include <modules/iam/nm_iam.h>

#include <nn/log.h>

struct thermostat {
    NabtoDevice* device;
    char* thermostatStateFile; // contains the thermostat specific state
    char* iamStateFile; // contains the iam state.
    char* deviceKeyFile;
    char* deviceConfigFile;
    struct nm_iam iam;
    struct nn_log* logger;
    struct thermostat_state state;
    struct thermostat_coap_handler coapGet;
    struct thermostat_coap_handler coapSetMode;
    struct thermostat_coap_handler coapSetPower;
    struct thermostat_coap_handler coapSetTarget;
};

void thermostat_init(struct thermostat* thermostat, NabtoDevice* device, struct nn_log* logger);
void thermostat_deinit(struct thermostat* thermostat);

void thermostat_reinit_state(struct thermostat* thermostat);

void thermostat_start(struct thermostat* thermostat);
void thermostat_stop(struct thermostat* thermostat);
void thermostat_update(struct thermostat* thermostat, double deltaTime);

void thermostat_set_mode(struct thermostat* thermostat, enum thermostat_mode mode);
void thermostat_set_power(struct thermostat* thermostat, bool power);
void thermostat_set_target(struct thermostat* thermostat, double target);
bool thermostat_check_access(struct thermostat* thermostat, NabtoDeviceCoapRequest* request, const char* action);

#endif
