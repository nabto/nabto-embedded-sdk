#ifndef NC_COAP_SERVER_H
#define NC_COAP_SERVER_H

#include <platform/np_platform.h>
#include <platform/np_dtls_srv.h>

#include <core/nc_client_connect.h>

#include <coap/nabto_coap_server.h>

struct nc_coap_server_context {
    struct np_platform* pl;
    struct nabto_coap_server server;
    uint32_t currentExpiry;
    struct np_event ev;
    struct np_timed_event timer;
    np_communication_buffer* sendBuffer;
    struct np_dtls_srv_send_context sendCtx;
    bool isSending;
};

void nc_coap_server_init(struct np_platform* pl, struct nc_coap_server_context* ctx);
void nc_coap_server_deinit(struct nc_coap_server_context* ctx);
void nc_coap_server_handle_packet(struct nc_coap_server_context* ctx, struct nc_client_connection* conn,
                           np_communication_buffer* buffer, uint16_t bufferSize);

struct nabto_coap_server* nc_coap_server_get_server(struct nc_coap_server_context* ctx);

void nc_coap_server_context_request_get_connection_id(struct nc_coap_server_context* ctx, struct nabto_coap_server_request* request, uint8_t* connectionId);

struct nc_client_connection* nc_coap_server_get_connection(struct nc_coap_server_context* ctx, struct nabto_coap_server_request* request);

void nc_coap_server_remove_connection(struct nc_coap_server_context* ctx, struct nc_client_connection* connection);

#endif // NC_COAP_SERVER_H
