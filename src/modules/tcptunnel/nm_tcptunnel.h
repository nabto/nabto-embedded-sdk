#ifndef _NM_TCPTUNNEL_H_
#define _NM_TCPTUNNEL_H_

#include <platform/np_platform.h>
#include <platform/np_tcp.h>
#include <platform/np_list.h>

#include <core/nc_stream_manager.h>
#include <core/nc_device.h>

struct nabto_stream;
struct nc_device_context;

#define NM_TCPTUNNEL_MAX_HOST_LENGTH 39

#define NM_TCPTUNNEL_BUFFER_SIZE 8192

struct nm_tcptunnel_connection {
    struct np_list_item connectionsListItem;
    struct np_platform* pl;
    np_tcp_socket* socket;
    struct nc_stream_context* stream;
    uint16_t port;
    struct np_ip_address address;
    uint8_t tcpRecvBuffer[NM_TCPTUNNEL_BUFFER_SIZE];
    size_t tcpRecvBufferSize;

    uint8_t streamRecvBuffer[NM_TCPTUNNEL_BUFFER_SIZE];
    size_t streamRecvBufferSize;
    size_t streamReadSize;

    bool tcpReadEnded;
    bool streamReadEnded;
};

struct nm_tcptunnel_service {
    struct np_list_item servicesListItem;
    struct nm_tcptunnel* next;
    struct nm_tcptunnel* prev;
    struct nm_tcptunnels* tunnels;

    struct np_ip_address address;
    uint16_t port;
    uint32_t streamPort;

    struct nc_stream_listener streamListener;

    struct np_list connections;

    char* id;
    char* type;
};

struct nm_tcptunnels {
    struct nc_device_context* device;
    struct np_list services;
    struct nc_connection_events_listener connectionEventsListener;

    struct nabto_coap_server_resource* coapListServices;
    struct nabto_coap_server_resource* coapGetService;
};

np_error_code nm_tcptunnels_init(struct nm_tcptunnels* tunnels, struct nc_device_context* device);
void nm_tcptunnels_deinit(struct nm_tcptunnels* tunnels);


struct nm_tcptunnel_service* nm_tcptunnel_service_create(struct nm_tcptunnels* tunnels);

np_error_code nm_tcptunnel_service_destroy_by_id(struct nm_tcptunnels* tunnels, const char* id);

np_error_code nm_tcptunnel_service_init(struct nm_tcptunnel_service* service, const char* id, const char* type, struct np_ip_address* address, uint16_t port);
void nm_tcptunnel_service_deinit(struct nm_tcptunnel_service* service);
np_error_code nm_tcptunnel_init_stream_listener(struct nm_tcptunnel_service* service);

struct nm_tcptunnel_service* nm_tcptunnels_find_service(struct nm_tcptunnels* tunnels, const char* id);

#endif
