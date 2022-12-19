#ifndef _TCP_TUNNEL_H_
#define _TCP_TUNNEL_H_

#include <nn/vector.h>
#include <nabto/nabto_device.h>
#include "tcp_tunnel_reachability_check.h"

struct tcp_tunnel {
    NabtoDevice* device;
    NabtoDeviceFuture* startFuture;
    NabtoDeviceFuture* closeFuture;

    struct nm_iam_configuration* iamConfig;
    struct nm_iam_state* tcpTunnelState;

    char* deviceConfigFile;
    char* stateFile;
    char* iamConfigFile;
    char* servicesFile;
    char* privateKeyFile;

    struct nn_vector services;
    struct tcp_tunnel_reachability_check reachabilityCheck;
};

bool tcp_tunnel_config_interactive(struct tcp_tunnel* tcpTunnel);
bool tcp_tunnel_demo_config(struct tcp_tunnel* tcpTunnel);
void tcp_tunnel_deinit(struct tcp_tunnel* tcpTunnel);

#endif
