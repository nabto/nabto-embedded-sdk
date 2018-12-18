#ifndef NC_RENDEZVOUS_H
#define NC_RENDEZVOUS_H

struct nc_rendezvous_context {
    struct nc_client_connection* conn;
};

void nc_rendezvous_init(struct nc_rendezvous_context* ctx,
                        struct nc_client_connection* conn);

void nc_rendezvous_handle_packet(struct nc_rendezvous_context* ctx,
                                 np_communication_buffer buffer,
                                 uint16_t bufferSize);

#endif // NC_RENDEZVOUS_H
