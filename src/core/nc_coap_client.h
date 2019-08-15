#ifndef NC_COAP_CLIENT_H
#define NC_COAP_CLIENT_H

#include <platform/np_platform.h>
#include <platform/np_dtls_cli.h>

#include <core/nc_client_connection.h>

#include <coap/nabto_coap_client.h>

struct nc_coap_client_context {
    struct np_platform* pl;
    struct nabto_coap_client client;
    uint32_t currentExpiry;
    struct np_event ev;
    struct np_timed_event timer;
    struct np_dtls_cli_send_context sendCtx;
    np_communication_buffer* sendBuffer;
    bool isSending;
};

void nc_coap_client_init(struct np_platform* pl, struct nc_coap_client_context* ctx);
void nc_coap_client_deinit(struct nc_coap_client_context* ctx);
void nc_coap_client_handle_packet(struct nc_coap_client_context* ctx,
                                  np_communication_buffer* buffer, uint16_t bufferSize, np_dtls_cli_context* dtls);

struct nabto_coap_client* nc_coap_client_get_client(struct nc_coap_client_context* ctx);

#endif // NC_COAP_CLIENT_H
