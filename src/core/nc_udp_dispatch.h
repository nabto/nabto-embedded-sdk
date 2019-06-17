#ifndef NC_UDP_DISPATCH_H
#define NC_UDP_DISPATCH_H

#include <platform/np_platform.h>

struct nc_stun_context;

//typedef void (*nc_udp_dispatch_send_callback)(const np_error_code ec, void* data);
typedef np_udp_packet_sent_callback nc_udp_dispatch_send_callback;
typedef void (*nc_udp_dispatch_create_callback)(const np_error_code ec, void* data);
typedef void (*nc_udp_dispatch_destroy_callback)(const np_error_code ec, void* data);

struct nc_udp_dispatch_context {
    struct np_platform* pl;
    struct np_udp_socket* sock;
    struct nc_client_connect_dispatch_context* cliConn;
    struct np_dtls_cli_context* dtls;
    struct nc_stun_context* stun;

    nc_udp_dispatch_destroy_callback destroyCb;
    void* destroyCbData;

    nc_udp_dispatch_create_callback createCb;
    void* createCbData;

};

void nc_udp_dispatch_async_create(struct nc_udp_dispatch_context* ctx, struct np_platform* pl, uint16_t port,
                                  nc_udp_dispatch_create_callback cb, void* data);

void nc_udp_dispatch_async_destroy(struct nc_udp_dispatch_context* ctx,
                                   nc_udp_dispatch_destroy_callback cb, void* data);

void nc_udp_dispatch_async_send_to(struct nc_udp_dispatch_context* ctx,
                                   struct np_udp_send_context* sender, struct np_udp_endpoint* ep,
                                   np_communication_buffer* buffer, uint16_t bufferSize,
                                   nc_udp_dispatch_send_callback cb, void* data);

uint16_t nc_udp_dispatch_get_local_port(struct nc_udp_dispatch_context* ctx);

// SET AND CLEAR CONTEXTS
void nc_udp_dispatch_set_client_connect_context(struct nc_udp_dispatch_context* ctx,
                                                struct nc_client_connect_dispatch_context* cliConn);

void nc_udp_dispatch_set_dtls_cli_context(struct nc_udp_dispatch_context* ctx,
                                          struct np_dtls_cli_context* dtls);

void nc_udp_dispatch_set_stun_context(struct nc_udp_dispatch_context* ctx,
                                      struct nc_stun_context* stun);

void nc_udp_dispatch_clear_client_connect_context(struct nc_udp_dispatch_context* ctx);
void nc_udp_dispatch_clear_dtls_cli_context(struct nc_udp_dispatch_context* ctx);
void nc_udp_dispatch_clear_stun_context(struct nc_udp_dispatch_context* ctx);
#endif // NC_UDP_DISPATCH_H
