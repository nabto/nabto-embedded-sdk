#ifndef NC_CLIENT_CONNECT_DISPATCH_H
#define NC_CLIENT_CONNECT_DISPATCH_H

#include <core/nc_client_connect.h>

#ifndef NABTO_MAX_CLIENT_CONNECTIONS
#define NABTO_MAX_CLIENT_CONNECTIONS 10
#endif

struct nc_udp_dispatch_context;

struct nc_client_connect_dispatch_element {
    struct nc_client_connection conn;
    bool active;
};

struct nc_client_connect_dispatch_context {
    struct np_platform* pl;
    struct nc_stream_manager_context* streamManager;
    struct nc_stun_context* stun;
    struct nc_coap_context* coap;
    struct nc_client_connect_dispatch_element elms[NABTO_MAX_CLIENT_CONNECTIONS];
};

void nc_client_connect_dispatch_init(struct nc_client_connect_dispatch_context* ctx,
                                     struct np_platform* pl,
                                     struct nc_stun_context* stun,
                                     struct nc_coap_context* coap,
                                     struct nc_stream_manager_context* streamManager);

void nc_client_connect_dispatch_handle_packet(struct nc_client_connect_dispatch_context* ctx,
                                              struct nc_udp_dispatch_context* udp, struct np_udp_endpoint ep,
                                              np_communication_buffer* buffer, uint16_t bufferSize);

np_error_code nc_client_connect_dispatch_close_connection(struct nc_client_connect_dispatch_context* ctx,
                                                          struct nc_client_connection* conn);

#endif
