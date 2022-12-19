#ifndef _TCP_TUNNEL_REACHABILITY_CHECK_H_
#define _TCP_TUNNEL_REACHABILITY_CHECK_H_

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <stdint.h>
#include <stdbool.h>
#include <nn/llist.h>

typedef void (*tcp_tunnel_reachability_check_callback)(NabtoDeviceError ec, void* userData);

struct tcp_tunnel_reachability_check_host {
    struct nn_llist_node hostsNode;
    char* host;
    uint16_t port;
    bool status;
};

struct tcp_tunnel_reachability_check {
    NabtoDevice* device;
    bool stopped;
    NabtoDeviceFuture* future;
    NabtoDeviceTcpProbe* probe;
    struct nn_llist hosts;
    struct nn_llist_iterator asyncIt;
    tcp_tunnel_reachability_check_callback asyncCb;
    void* asyncUserData;
};

bool tcp_tunnel_reachability_check_init(struct tcp_tunnel_reachability_check* ttrc, NabtoDevice* device);
void tcp_tunnel_reachability_check_deinit(struct tcp_tunnel_reachability_check* ttrc);

void tcp_tunnel_reachability_check_stop(struct tcp_tunnel_reachability_check* ttrc);

bool tcp_tunnel_reachability_check_blocking(struct tcp_tunnel_reachability_check* ttrc);

void tcp_tunnel_reachability_check_async(struct tcp_tunnel_reachability_check* ttrc, tcp_tunnel_reachability_check_callback cb, void* userData);

bool tcp_tunnel_reachability_check_add_host(struct tcp_tunnel_reachability_check* ttrc, const char* host, uint16_t port);

#endif
