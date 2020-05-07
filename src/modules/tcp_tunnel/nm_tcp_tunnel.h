#ifndef _NM_TCP_TUNNEL_H_
#define _NM_TCP_TUNNEL_H_

#include <platform/np_platform.h>
#include <platform/np_tcp.h>

#include <core/nc_stream_manager.h>
#include <core/nc_device.h>

#include <nn/llist.h>

struct nabto_stream;
struct nc_device_context;

#define NM_TCP_TUNNEL_MAX_HOST_LENGTH 39

#define NM_TCP_TUNNEL_BUFFER_SIZE 8192

struct nm_tcp_tunnel_connection {
    struct nn_llist_node connectionsListItem;
    struct np_platform* pl;
    np_tcp_socket* socket;
    struct nc_stream_context* stream;
    struct np_ip_address address;
    uint16_t port;
    uint8_t tcpRecvBuffer[NM_TCP_TUNNEL_BUFFER_SIZE];
    size_t tcpRecvBufferSize;

    uint8_t streamRecvBuffer[NM_TCP_TUNNEL_BUFFER_SIZE];
    size_t streamRecvBufferSize;
    size_t streamReadSize;

    bool tcpReadEnded;
    bool streamReadEnded;

    struct np_completion_event connectCompletionEvent;
    struct np_completion_event readCompletionEvent;
    size_t readLength;
    struct np_completion_event writeCompletionEvent;
};

struct nm_tcp_tunnel_service {
    struct nn_llist_node servicesListItem;
    struct nm_tcp_tunnel* next;
    struct nm_tcp_tunnel* prev;
    struct nm_tcp_tunnels* tunnels;

    struct np_ip_address address;
    uint16_t port;
    uint32_t streamPort;

    struct nc_stream_listener streamListener;

    struct nn_llist connections;

    char* id;
    char* type;

    void* weakPtr;
};

struct nm_tcp_tunnels {
    struct nc_device_context* device;
    struct nn_llist services;
    uint8_t* weakPtrCounter;

    struct nabto_coap_server_resource* coapListServices;
    struct nabto_coap_server_resource* coapGetService;
};

np_error_code nm_tcp_tunnels_init(struct nm_tcp_tunnels* tunnels, struct nc_device_context* device);
void nm_tcp_tunnels_deinit(struct nm_tcp_tunnels* tunnels);


struct nm_tcp_tunnel_service* nm_tcp_tunnel_service_create(struct nm_tcp_tunnels* tunnels);

np_error_code nm_tcp_tunnel_service_destroy_by_id(struct nm_tcp_tunnels* tunnels, const char* id);

np_error_code nm_tcp_tunnel_service_init(struct nm_tcp_tunnel_service* service, const char* id, const char* type, struct np_ip_address* address, uint16_t port);
void nm_tcp_tunnel_service_deinit(struct nm_tcp_tunnel_service* service);
np_error_code nm_tcp_tunnel_init_stream_listener(struct nm_tcp_tunnel_service* service);

struct nm_tcp_tunnel_service* nm_tcp_tunnels_find_service(struct nm_tcp_tunnels* tunnels, const char* id);
struct nm_tcp_tunnel_service* nm_tcp_tunnels_find_service_by_weak_ptr(struct nm_tcp_tunnels* tunnels, void* weakPtr);

#endif
