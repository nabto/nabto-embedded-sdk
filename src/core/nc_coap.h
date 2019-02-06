#ifndef NC_COAP_H
#define NC_COAP_H

#include <platform/np_platform.h>
#include <platform/np_dtls_srv.h>

#include <core/nc_client_connect.h>

#include <coap2/nabto_coap_server.h>

struct nc_coap_context {
    struct np_platform* pl;
    struct nabto_coap_server server;
    uint32_t currentExpiry;
    struct np_event ev;
    struct np_timed_event timer;
    np_communication_buffer* sendBuffer;
    struct np_dtls_srv_send_context sendCtx;
};

void nc_coap_init(struct np_platform* pl, struct nc_coap_context* ctx);
void nc_coap_handle_packet(struct nc_coap_context* ctx, struct nc_client_connection* conn,
                           np_communication_buffer* buffer, uint16_t bufferSize);

struct nabto_coap_server* nc_coap_get_server(struct nc_coap_context* ctx);

#endif // NC_COAP_H
