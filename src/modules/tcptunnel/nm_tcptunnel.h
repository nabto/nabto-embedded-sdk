#ifndef _NM_TCPTUNNEL_H_
#define _NM_TCPTUNNEL_H_

#include <platform/np_platform.h>
#include <platform/np_tcp.h>

struct nabto_stream;

#define NM_TCPTUNNEL_MAX_HOST_LENGTH 39

struct nm_tcptunnel_connection {
    struct nm_tcptunnel_connection* next;
    struct nm_tcptunnel_connection* prev;
    struct nm_tcptunnel* tunnel;
    struct np_platform* pl;
    np_tcp_socket* socket;
    struct nc_stream_context* stream;

    void* tcpRecvBuffer;
    size_t tcpRecvBufferSize;

    void* streamRecvBuffer;
    size_t streamRecvBufferSize;
    size_t streamReadSize;
};

struct nm_tcptunnel {
    struct nm_tcptunnel* next;
    struct nm_tcptunnel* prev;
    struct nm_tcptunnels* tunnels;
    int id; // id to use in the CoAP api paths
    struct np_ip_address address;
    uint16_t port;
    struct nm_tcptunnel_connection connectionsSentinel;
};

struct nm_tcptunnels {
    int idCounter;
    struct np_ip_address defaultHost;
    uint16_t defaultPort;
    struct nm_tcptunnel tunnelsSentinel;
};

void nm_tcptunnel_init();

struct nm_tcptunnel* nm_tcptunnel_create(struct nm_tcptunnels* tunnels);


#endif
