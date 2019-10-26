#ifndef _HEATPUMP_APPLICATION_H_
#define _HEATPUMP_APPLICATION_H_

#include "heat_pump.hpp"

#include <nabto/nabto_device.h>

void heat_pump_coap_init(NabtoDevice* device, HeatPump* heatpump);
void heat_pump_coap_deinit(HeatPump* heatPump);

#endif
