#ifndef _NM_TCPTUNNEL_H_
#define _NM_TCPTUNNEL_H_

#include <platform/np_platform.h>
#include <platform/np_tcp.h>

#include <core/nc_stream_manager.h>
#include <core/nc_device.h>

struct nabto_stream;
struct nc_device_context;

#define NM_TCPTUNNEL_MAX_HOST_LENGTH 39

struct nm_tcptunnel_connection {
    struct nm_tcptunnel_connection* next;
    struct nm_tcptunnel_connection* prev;
    struct np_platform* pl;
    np_tcp_socket* socket;
    struct nc_stream_context* stream;
    struct np_ip_address address;
    uint16_t port;
    uint8_t tcpRecvBuffer[1024];
    size_t tcpRecvBufferSize;

    uint8_t streamRecvBuffer[1024];
    size_t streamRecvBufferSize;
    size_t streamReadSize;

    bool tcpReadEnded;
    bool streamReadEnded;
};

struct nm_tcptunnel {
    struct nm_tcptunnel* next;
    struct nm_tcptunnel* prev;
    struct nm_tcptunnels* tunnels;
    int id; // id to use in the CoAP api paths
    struct np_ip_address address;
    uint16_t port;
    struct nm_tcptunnel_connection connectionsSentinel;
    uint32_t streamPort;
    struct nc_stream_listener streamListener;
    char tunnelId[17]; // It has room for a 64 bit integer encoded in hex.
    // connectionRef for the connection which created the tunnel.
    uint64_t connectionRef;
};

struct nm_tcptunnels {
    struct nc_device_context* device;
    uint64_t idCounter;
    struct np_ip_address defaultHost;
    uint16_t defaultPort;
    struct nm_tcptunnel tunnelsSentinel;
    struct nc_connection_events_listener connectionEventsListener;
};

np_error_code nm_tcptunnels_init(struct nm_tcptunnels* tunnels, struct nc_device_context* device);
void nm_tcptunnels_deinit(struct nm_tcptunnels* tunnels);


struct nm_tcptunnel* nm_tcptunnel_create(struct nm_tcptunnels* tunnels);

void nm_tcptunnel_init(struct nm_tcptunnel* tunnel, struct np_ip_address* address, uint16_t port);
void nm_tcptunnel_deinit(struct nm_tcptunnel* tunnel);
np_error_code nm_tcptunnel_init_stream_listener(struct nm_tcptunnel* tunnel);

void nm_tcptunnel_remove_connection(struct nm_tcptunnel_connection* connection);

#endif
