#ifndef NC_COAP_SERVER_H
#define NC_COAP_SERVER_H

#include <platform/np_platform.h>
#include <platform/np_dtls_cli.h>

#include <core/nc_client_connection.h>

#include <coap/nabto_coap_server.h>

struct nc_coap_server_context {
    struct np_platform* pl;
    struct nabto_coap_server server;
    struct nabto_coap_server_requests requests;
    uint32_t currentExpiry;
    struct np_event* ev;
    struct np_event* timer;
    // if sendBuffer is non null that means we are currently sending a packet.
    struct np_communication_buffer* sendBuffer;
    struct np_dtls_send_context sendCtx;
};

// translate nabto_coap_error to np_error_code, coap errors are common
// for server and client, nc_coap_server_ prefix refers to the fact
// the function happens to be defined in nc_coap_server.c
np_error_code nc_coap_server_error_module_to_core(nabto_coap_error ec);
np_error_code nc_coap_server_init(struct np_platform* pl, struct nn_log* logger, struct nc_coap_server_context* ctx);
void nc_coap_server_deinit(struct nc_coap_server_context* ctx);
void nc_coap_server_handle_packet(struct nc_coap_server_context* ctx, struct nc_client_connection* conn,
                                  uint8_t* buffer, uint16_t bufferSize);

struct nabto_coap_server* nc_coap_server_get_server(struct nc_coap_server_context* ctx);

void nc_coap_server_context_request_get_connection_id(struct nc_coap_server_context* ctx, struct nabto_coap_server_request* request, uint8_t* connectionId);

struct nc_client_connection* nc_coap_server_get_connection(struct nc_coap_server_context* ctx, struct nabto_coap_server_request* request);

void nc_coap_server_remove_connection(struct nc_coap_server_context* ctx, struct nc_client_connection* connection);

void nc_coap_server_limit_requests(struct nc_coap_server_context* ctx, size_t limit);

#endif // NC_COAP_SERVER_H
