#ifndef NC_RENDEZVOUS_H
#define NC_RENDEZVOUS_H

#include <platform/np_platform.h>

struct nc_rendezvous_context {
    struct nc_client_connection* conn;
    struct np_dtls_srv_connection* dtls;
};

void nc_rendezvous_init(struct nc_rendezvous_context* ctx,
                        struct nc_client_connection* conn,
                        struct np_dtls_srv_connection* dtls);

void nc_rendezvous_handle_packet(struct nc_rendezvous_context* ctx,
                                 np_communication_buffer* buffer,
                                 uint16_t bufferSize);

#endif // NC_RENDEZVOUS_H
