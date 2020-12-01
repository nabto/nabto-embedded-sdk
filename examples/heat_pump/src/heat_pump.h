#ifndef _HEAT_PUMP_H_
#define _HEAT_PUMP_H_

#include "heat_pump_coap_handler.h"
#include "heat_pump_state.h"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>



#include <modules/iam/nm_iam.h>

#include <nn/log.h>

struct heat_pump {
    NabtoDevice* device;
    char* heatPumpStateFile; // contains the heat pump specific state
    char* iamStateFile; // contains the iam state.
    char* deviceKeyFile;
    char* deviceConfigFile;
    struct nm_iam iam;
    struct nn_log* logger;
    struct heat_pump_state state;
    struct heat_pump_coap_handler coapGet;
    struct heat_pump_coap_handler coapSetMode;
    struct heat_pump_coap_handler coapSetPower;
    struct heat_pump_coap_handler coapSetTarget;
};

void heat_pump_init(struct heat_pump* heatPump, NabtoDevice* device, struct nn_log* logger);
void heat_pump_deinit(struct heat_pump* heatPump);

void heat_pump_start(struct heat_pump* heatPump);
void heat_pump_stop(struct heat_pump* heatPump);

void heat_pump_set_mode(struct heat_pump* heatPump, enum heat_pump_mode mode);
void heat_pump_set_power(struct heat_pump* heatPump, bool power);
void heat_pump_set_target(struct heat_pump* heatPump, double target);
bool heat_pump_check_access(struct heat_pump* heatPump, NabtoDeviceCoapRequest* request, const char* action);

#endif
