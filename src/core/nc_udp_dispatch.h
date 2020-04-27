#ifndef NC_UDP_DISPATCH_H
#define NC_UDP_DISPATCH_H

#include <platform/np_platform.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nc_stun_context;

typedef void (*nc_udp_dispatch_bind_callback)(const np_error_code ec, void* data);

struct nc_udp_dispatch_context {
    struct np_platform* pl;
    struct np_udp_socket* sock;
    struct nc_client_connection_dispatch_context* cliConn;
    struct np_dtls_cli_context* dtls;
    struct nc_stun_context* stun;

    nc_udp_dispatch_bind_callback bindCb;
    void* bindCbData;

};

np_error_code nc_udp_dispatch_init(struct nc_udp_dispatch_context* ctx, struct np_platform* pl);
void nc_udp_dispatch_deinit(struct nc_udp_dispatch_context* ctx);

np_error_code nc_udp_dispatch_async_bind(struct nc_udp_dispatch_context* ctx, struct np_platform* pl, uint16_t port,
                                         nc_udp_dispatch_bind_callback cb, void* data);
np_error_code nc_udp_dispatch_abort(struct nc_udp_dispatch_context* ctx);

np_error_code nc_udp_dispatch_async_send_to(struct nc_udp_dispatch_context* ctx, struct np_udp_endpoint* ep,
                                            uint8_t* buffer, uint16_t bufferSize,
                                            struct np_completion_event* completionEvent);

uint16_t nc_udp_dispatch_get_local_port(struct nc_udp_dispatch_context* ctx);

// SET AND CLEAR CONTEXTS
void nc_udp_dispatch_set_client_connection_context(struct nc_udp_dispatch_context* ctx,
                                                struct nc_client_connection_dispatch_context* cliConn);

void nc_udp_dispatch_set_dtls_cli_context(struct nc_udp_dispatch_context* ctx,
                                          struct np_dtls_cli_context* dtls);

void nc_udp_dispatch_set_stun_context(struct nc_udp_dispatch_context* ctx,
                                      struct nc_stun_context* stun);

void nc_udp_dispatch_clear_client_connection_context(struct nc_udp_dispatch_context* ctx);
void nc_udp_dispatch_clear_dtls_cli_context(struct nc_udp_dispatch_context* ctx);
void nc_udp_dispatch_clear_stun_context(struct nc_udp_dispatch_context* ctx);

#ifdef __cplusplus
} // extern c
#endif


#endif // NC_UDP_DISPATCH_H
