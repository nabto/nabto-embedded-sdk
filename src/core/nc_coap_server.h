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

struct nc_coap_server_request {
    struct nabto_coap_server_request* request;
};

typedef void (*nc_coap_server_resource_handler)(struct nc_coap_server_request *request, void *userData);


struct nc_coap_server_resource {
    struct nabto_coap_server_resource* resource;
    nc_coap_server_resource_handler handler;
    void* userData;
};

// translate nabto_coap_error to np_error_code, coap errors are common
// for server and client, nc_coap_server_ prefix refers to the fact
// the function happens to be defined in nc_coap_server.c
np_error_code nc_coap_server_error_module_to_core(nabto_coap_error ec);
np_error_code nc_coap_server_init(struct np_platform* pl, struct nn_log* logger, struct nc_coap_server_context* ctx);
void nc_coap_server_deinit(struct nc_coap_server_context* ctx);
void nc_coap_server_handle_packet(struct nc_coap_server_context* ctx, struct nc_client_connection* conn,
                                  uint8_t* buffer, uint16_t bufferSize);


bool nc_coap_server_context_request_get_connection_id(struct nc_coap_server_context* ctx, struct nc_coap_server_request* request, uint8_t* connectionId);

void nc_coap_server_remove_connection(struct nc_coap_server_context* ctx, struct nc_client_connection* connection);

void nc_coap_server_limit_requests(struct nc_coap_server_context* ctx, size_t limit);


nabto_coap_error nc_coap_server_add_resource(struct nc_coap_server_context* server, nabto_coap_code method, const char** segments, nc_coap_server_resource_handler handler, void* userData, struct nc_coap_server_resource** resource);

void nc_coap_server_remove_resource(struct nc_coap_server_resource* resource);

nabto_coap_error nc_coap_server_send_error_response(struct nc_coap_server_request* request, nabto_coap_code status, const char* description);

void nc_coap_server_response_set_code(struct nc_coap_server_request* request, nabto_coap_code code);
void nc_coap_server_response_set_code_human(struct nc_coap_server_request* request, uint16_t humanCode);

nabto_coap_error nc_coap_server_response_set_payload(struct nc_coap_server_request* request, const void* data, size_t dataSize);

void nc_coap_server_response_set_content_format(struct nc_coap_server_request* request, uint16_t format);

nabto_coap_error nc_coap_server_response_ready(struct nc_coap_server_request* request);

void nc_coap_server_request_free(struct nc_coap_server_request* request);

/**
 * Get content format, if no content format is present return -1 else
 * a contentFormat between 0 and 2^16-1 is returned.
 */
int32_t nc_coap_server_request_get_content_format(struct nc_coap_server_request* request);

bool nc_coap_server_request_get_payload(struct nc_coap_server_request* request, void** payload, size_t* payloadLength);

void* nc_coap_server_request_get_connection(struct nc_coap_server_request* request);

const char* nc_coap_server_request_get_parameter(struct nc_coap_server_request* request, const char* parameter);



#endif // NC_COAP_SERVER_H
