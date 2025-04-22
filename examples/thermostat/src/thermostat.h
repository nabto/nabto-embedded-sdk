#ifndef THERMOSTAT_H_
#define THERMOSTAT_H_

#include "thermostat_coap_handler.h"
#include "thermostat_iam.h"
#include "thermostat_state.h"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "thermostat_state.h"

#include <modules/iam/nm_iam.h>

#include <nn/log.h>

struct thermostat {
    NabtoDevice* device;
    struct nm_iam* iam;
    struct nn_log* logger;
    struct thermostat_state* state;
    struct thermostat_coap_handler coapGet;
    struct thermostat_coap_handler coapSetMode;
    struct thermostat_coap_handler coapSetPower;
    struct thermostat_coap_handler coapSetTarget;
    // compabibility handlers such that apps which uses the heatpump api is
    // still compatible with this example.
    struct thermostat_coap_handler coapGetLegacy;
    struct thermostat_coap_handler coapSetModeLegacy;
    struct thermostat_coap_handler coapSetPowerLegacy;
    struct thermostat_coap_handler coapSetTargetLegacy;

};

void thermostat_init(struct thermostat* thermostat, NabtoDevice* device, struct nm_iam* iam, struct thermostat_state* state, struct nn_log* logger);
void thermostat_deinit(struct thermostat* thermostat);

void thermostat_stop(struct thermostat* thermostat);
void thermostat_update(struct thermostat* thermostat, double deltaTime);

bool thermostat_check_access(struct thermostat* thermostat, NabtoDeviceCoapRequest* request, const char* action);


#endif
