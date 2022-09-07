#ifndef _THERMOSTAT_H_
#define _THERMOSTAT_H_

#include "thermostat_coap_handler.h"
#include "thermostat_iam.h"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>



#include <modules/iam/nm_iam.h>

#include <nn/log.h>

enum thermostat_mode {
    THERMOSTAT_MODE_COOL,
    THERMOSTAT_MODE_HEAT,
    THERMOSTAT_MODE_DRY,
    THERMOSTAT_MODE_FAN
};

struct thermostat_state {
    bool power;
    double target;
    double temperature;
    enum thermostat_mode mode;
};

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
    // compabibility handlers such that apps which uses the heatpump api is
    // still compatible with this example.
    struct thermostat_coap_handler coapGetLegacy;
    struct thermostat_coap_handler coapSetModeLegacy;
    struct thermostat_coap_handler coapSetPowerLegacy;
    struct thermostat_coap_handler coapSetTargetLegacy;

};

const char* mode_as_string(enum thermostat_mode mode);

void thermostat_init(struct thermostat* thermostat, NabtoDevice* device, const char* homeDir, struct nn_log* logger);
void thermostat_deinit(struct thermostat* thermostat);

void thermostat_reinit_state(struct thermostat* thermostat);

void thermostat_stop(struct thermostat* thermostat);
void thermostat_update(struct thermostat* thermostat, double deltaTime);

void thermostat_set_mode(struct thermostat* thermostat, enum thermostat_mode mode);
void thermostat_set_power(struct thermostat* thermostat, bool power);
void thermostat_set_target(struct thermostat* thermostat, double target);
bool thermostat_check_access(struct thermostat* thermostat, NabtoDeviceCoapRequest* request, const char* action);


#endif
