#ifndef _HEATPUMP_APPLICATION_H_
#define _HEATPUMP_APPLICATION_H_

#include "heatpump.hpp"

#include <nabto/nabto_device.h>

void heatpump_coap_init(NabtoDevice* device, Heatpump* heatpump);

#endif
