#include "nc_rendezvous.h"

void nc_rendezvous_init(struct nc_rendezvous_context* ctx,
                        struct nc_client_connection* conn,
                        struct np_dtls_srv_connection* dtls)
{
    ctx->conn = conn;
    ctx->dtls = dtls;
}

void nc_rendezvous_handle_packet(struct nc_rendezvous_context* ctx,
                                 np_communication_buffer* buffer,
                                 uint16_t bufferSize)
{

}
