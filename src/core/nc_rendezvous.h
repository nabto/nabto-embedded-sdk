#ifndef NC_RENDEZVOUS_H
#define NC_RENDEZVOUS_H

#include <platform/np_platform.h>
#include <platform/np_dtls_srv.h>

struct nc_rendezvous_context {
    struct np_platform* pl;
    struct nc_client_connection* conn;
    struct np_dtls_srv_connection* dtls;
    struct nc_stun_context* stun;
    struct nc_coap_server_context* coap;

    struct nabto_coap_server_request* stunRequest;

    struct np_dtls_srv_send_context sendCtx;

    np_communication_buffer* priBuf;
    np_communication_buffer* secBuf;

    struct np_udp_endpoint epList[10];
    // index of first empty spot in epList
    uint8_t epIndex;
    bool sendingDevReqs;

    struct np_udp_endpoint cliRespEp;
};

void nc_rendezvous_init(struct nc_rendezvous_context* ctx,
                        struct np_platform* pl,
                        struct nc_client_connection* conn,
                        struct np_dtls_srv_connection* dtls,
                        struct nc_stun_context* stun,
                        struct nc_coap_server_context* coap);

void nc_rendezvous_destroy(struct nc_rendezvous_context* ctx);

void nc_rendezvous_handle_packet(struct nc_rendezvous_context* ctx,
                                 np_udp_endpoint ep,
                                 np_communication_buffer* buffer,
                                 uint16_t bufferSize);

#endif // NC_RENDEZVOUS_H
