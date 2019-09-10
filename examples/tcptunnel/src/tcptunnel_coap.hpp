#pragma once

#include <nabto/nabto_device.h>

class TcpTunnel;

void tcptunnel_coap_init(NabtoDevice* device, TcpTunnel* application);
