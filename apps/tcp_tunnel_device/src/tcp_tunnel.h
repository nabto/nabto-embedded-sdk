#ifndef _TCP_TUNNEL_H_
#define _TCP_TUNNEL_H_

#include <nn/vector.h>

struct tcp_tunnel {
    char* deviceConfigFile;
    char* stateFile;
    char* iamConfigFile;
    char* servicesFile;
    char* privateKeyFile;

    struct nn_vector services;
};

bool tcp_tunnel_config_interactive(struct tcp_tunnel* tcpTunnel);
bool tcp_tunnel_demo_config(struct tcp_tunnel* tcpTunnel);
void tcp_tunnel_deinit(struct tcp_tunnel* tcpTunnel);

#endif
