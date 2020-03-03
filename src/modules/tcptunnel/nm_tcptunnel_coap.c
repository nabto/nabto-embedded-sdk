#include "nm_tcptunnel.h"
#include "nm_tcptunnel_coap.h"

#include <core/nc_coap_server.h>
#include <core/nc_coap.h>
#include <platform/np_logging.h>

#include <cbor.h>

#define LOG NABTO_LOG_MODULE_TUNNEL

static void create_tunnel(struct nabto_coap_server_request* request, void* data);
static void delete_tunnel(struct nabto_coap_server_request* request, void* data);
static void get_tunnel(struct nabto_coap_server_request* request, void* data);
static void create_tunnel_iam(bool allow, void* userData1, void* userData2);
static void delete_tunnel_iam(bool allow, void* userData1, void* userData2);
static void get_tunnel_iam(bool allow, void* userData1, void* userData2);

static struct nm_tcptunnel* find_tunnel(struct nm_tcptunnels* tunnels, const char* tid);

np_error_code nm_tcptunnel_coap_init(struct nm_tcptunnels* tunnels, struct nc_coap_server_context* server)
{
    nabto_coap_error err = nabto_coap_server_add_resource(&server->server, NABTO_COAP_CODE_POST,
                                                          (const char*[]){"tcptunnels", NULL},
                                                          create_tunnel, tunnels, &tunnels->coapPostRes);
    if (err != NABTO_COAP_ERROR_OK) {
        nm_tcptunnel_coap_deinit(tunnels);
        return nc_coap_error_to_core(err);
    }
    err = nabto_coap_server_add_resource(&server->server, NABTO_COAP_CODE_DELETE,
                                         (const char*[]){"tcptunnels", "{tid}", NULL},
                                         delete_tunnel, tunnels, &tunnels->coapDelRes);
    if (err != NABTO_COAP_ERROR_OK) {
        nm_tcptunnel_coap_deinit(tunnels);
        return nc_coap_error_to_core(err);
    }
    err = nabto_coap_server_add_resource(&server->server, NABTO_COAP_CODE_GET,
                                         (const char*[]){"tcptunnels", "{tid}", NULL},
                                         get_tunnel, tunnels, &tunnels->coapGetRes);
    if (err != NABTO_COAP_ERROR_OK) {
        nm_tcptunnel_coap_deinit(tunnels);
        return nc_coap_error_to_core(err);
    }
    return NABTO_EC_OK;
}

void nm_tcptunnel_coap_deinit(struct nm_tcptunnels* tunnels)
{
    if (tunnels->coapPostRes) {
        nabto_coap_server_remove_resource(tunnels->coapPostRes);
        tunnels->coapPostRes = NULL;
    }
    if (tunnels->coapDelRes) {
        nabto_coap_server_remove_resource(tunnels->coapDelRes);
        tunnels->coapDelRes = NULL;
    }
    if (tunnels->coapGetRes) {
    nabto_coap_server_remove_resource(tunnels->coapGetRes);
        tunnels->coapGetRes = NULL;
    }

}

bool parse_port(struct nabto_coap_server_request* request, struct nm_tcptunnels* tunnels, uint16_t* port)
{
    int32_t contentFormat;
    contentFormat = nabto_coap_server_request_get_content_format(request);

    if (contentFormat != NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        // if we cant send error response, free will auto-reply with 500
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,00), "Content format not CBOR");
        return false;
    }

    void* payload;
    size_t payloadLength;
    if (!nabto_coap_server_request_get_payload(request, &payload, &payloadLength)) {
        // if we cant send error response, free will auto-reply with 500
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,00), "No payload, Port is required");
        return false;
    }

    CborParser parser;
    CborValue map;
    if (cbor_parser_init(payload, payloadLength, 0, &parser, &map) != CborNoError) {
        // if we cant send error response, free will auto-reply with 500
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(5,00), "Internal CBOR error");
        return false;
    }

    if (!cbor_value_is_map(&map)) {
        // if we cant send error response, free will auto-reply with 500
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,00), "Invalid payload, not CBOR map");
        return false;
    }

    CborValue value;
    uint64_t p;
    if (cbor_value_map_find_value(&map, "Port", &value) == CborNoError &&
        cbor_value_is_unsigned_integer(&value))
    {
        if (cbor_value_get_uint64(&value, &p) != CborNoError)  {
            // if we cant send error response, free will auto-reply with 500
            nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(5,00), "Internal CBOR error");
            return false;
        }
        *port = (uint16_t)p;
    } else {
        // if we cant send error response, free will auto-reply with 500
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,00), "Port missing");
        return false;
    }

    return true;
}

static char* integerToAscii(uint64_t value)
{
    static char outBuffer[25];
    memset(outBuffer, 0, 25);
    sprintf(outBuffer, "%"PRId64, value);
    return outBuffer;
}

/**
 * Create a tunnel.
 *
 * Request format
 * {
 *   "Ip": bytes
 *   "Port": integer
 * }
 */
void create_tunnel(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;
    // Read host and port, insert default if not exists.
    uint16_t port;

    if (!parse_port(request, tunnels, &port)) {
        // If parse failed, the function has send an error response
        nabto_coap_server_request_free(request);
        return;
    }

    struct np_platform* pl = tunnels->device->pl;
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    struct np_authorization_request* authReq = pl->authorization.create_request(pl, connection->connectionRef, "TcpTunnel:Create");
    if (authReq != NULL &&
        pl->authorization.add_string_attribute(authReq, "TcpTunnel:Port", integerToAscii(port)) == NABTO_EC_OK)
    {
        pl->authorization.check_access(authReq, create_tunnel_iam, tunnels, request);
        return;
    }

    // Could not make the iam request
    pl->authorization.discard_request(authReq);
    nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(5,00), "Out of resources");
    nabto_coap_server_request_free(request);
}

void create_tunnel_iam(bool allow, void* userData1, void* userData2)
{
    struct nm_tcptunnels* tunnels = userData1;
    struct nabto_coap_server_request* request = userData2;

    if (!allow) {
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,03), NULL);
        nabto_coap_server_request_free(request);
        return;
    }
    // Read port, insert default if not exists.
    uint16_t port;

    if (!parse_port(request, tunnels, &port)) {
        // If parse failed, the function has send an error response
        nabto_coap_server_request_free(request);
        return;
    }
    // Create tunnel resource.
    struct nm_tcptunnel* tunnel = nm_tcptunnel_create(tunnels);
    nm_tcptunnel_init(tunnel, port);
    nm_tcptunnel_init_stream_listener(tunnel);
    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);
    tunnel->connectionRef = connection->connectionRef;

    uint8_t cborResponse[128];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, cborResponse, 128, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "TunnelId");
    cbor_encode_text_stringz(&map, tunnel->tunnelId);
    cbor_encode_text_stringz(&map, "StreamPort");
    cbor_encode_uint(&map, tunnel->streamPort);
    cbor_encoder_close_container(&encoder, &map);
    size_t extra = cbor_encoder_get_extra_bytes_needed(&encoder);
    if (extra != 0) {
        NABTO_LOG_ERROR(LOG, "Create tunnel CBOR response buffer too small. Should be impossible.");
    }
    size_t used = cbor_encoder_get_buffer_size(&encoder, cborResponse);

    NABTO_LOG_INFO(LOG, "Created tcp tunnel. destination port %" PRIu16, port);
    // Return 201 Created.
    nabto_coap_server_response_set_code(request, NABTO_COAP_CODE(2,01));
    nabto_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);

    nabto_coap_error err = nabto_coap_server_response_set_payload(request, cborResponse, used);
    if (err != NABTO_COAP_ERROR_OK) {
        nm_tcptunnel_deinit(tunnel);
        // Dont try to add a payload on OOM it would propably fail
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(5,00), NULL);
    } else {
        // On errors we should still cleanup the request
        nabto_coap_server_response_ready(request);
    }
    nabto_coap_server_request_free(request);
}

/**
 * CoAP DELETE /tunnels/:tid
 */
void delete_tunnel(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;

    struct nm_tcptunnel* tunnel = find_tunnel(tunnels, nabto_coap_server_request_get_parameter(request, "tid"));
    if (tunnel == NULL) {
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,04), NULL);
        nabto_coap_server_request_free(request);
        return;
    }

    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    if (tunnel->connectionRef != connection->connectionRef) {
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,03), NULL);
        nabto_coap_server_request_free(request);
        return;
    }

    struct np_platform* pl = tunnels->device->pl;

    struct np_authorization_request* authReq = pl->authorization.create_request(pl, connection->connectionRef, "TcpTunnel:Delete");
    if (authReq) {
        pl->authorization.check_access(authReq, delete_tunnel_iam, tunnels, request);
        return;
    }

    // Could not make the iam request
    pl->authorization.discard_request(authReq);
    nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(5,00), "Out of resources");
    nabto_coap_server_request_free(request);
}

void delete_tunnel_iam(bool allow, void* userData1, void* userData2)
{
    struct nm_tcptunnels* tunnels = userData1;
    struct nabto_coap_server_request* request = userData2;

    if (!allow) {
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,03), NULL);
        nabto_coap_server_request_free(request);
        return;
    }

    struct nm_tcptunnel* tunnel = find_tunnel(tunnels, nabto_coap_server_request_get_parameter(request, "tid"));
    if (tunnel == NULL) {
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,04), NULL);
        nabto_coap_server_request_free(request);
        return;
    }
    nm_tcptunnel_deinit(tunnel);

    nabto_coap_server_response_set_code(request, NABTO_COAP_CODE(2,02));
    // On errors we should still cleanup the request
    nabto_coap_server_response_ready(request);
    nabto_coap_server_request_free(request);
}

void get_tunnel(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;
    struct nm_tcptunnel* tunnel = find_tunnel(tunnels, nabto_coap_server_request_get_parameter(request, "tid"));
    if (tunnel == NULL) {
        // OOM impossible with NULL message
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,04), NULL);
        nabto_coap_server_request_free(request);
        return;
    }

    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);
    if (tunnel->connectionRef != connection->connectionRef) {
        // OOM impossible with NULL message
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,03), NULL);
        nabto_coap_server_request_free(request);
        return;
    }


    struct np_platform* pl = tunnels->device->pl;
    struct np_authorization_request* authReq = pl->authorization.create_request(pl, connection->connectionRef, "TcpTunnel:Get");
    if (authReq) {
        pl->authorization.check_access(authReq, get_tunnel_iam, tunnels, request);
        return;
    }

    // Could not make the iam request
    pl->authorization.discard_request(authReq);
    nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(5,00), NULL);
    nabto_coap_server_request_free(request);
}

void get_tunnel_iam(bool allow, void* userData1, void* userData2)
{
    struct nm_tcptunnels* tunnels = userData1;
    struct nabto_coap_server_request* request = userData2;
    struct nm_tcptunnel* tunnel = find_tunnel(tunnels, nabto_coap_server_request_get_parameter(request, "tid"));
    if (tunnel == NULL) {
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(4,04), NULL);
        nabto_coap_server_request_free(request);
        return;
    }

    uint8_t cborResponse[128];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, cborResponse, 128, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "StreamPort");
    cbor_encode_uint(&map, tunnel->streamPort);

    cbor_encode_text_stringz(&map, "Port");
    cbor_encode_uint(&map, tunnel->port);
    cbor_encoder_close_container(&encoder, &map);
    size_t extra = cbor_encoder_get_extra_bytes_needed(&encoder);
    if (extra != 0) {
        NABTO_LOG_ERROR(LOG, "Create tunnel CBOR response buffer too small. Should be impossible.");
    }
    size_t used = cbor_encoder_get_buffer_size(&encoder, cborResponse);

    // Return 201 Created.
    nabto_coap_server_response_set_code(request, NABTO_COAP_CODE(2,05));
    nabto_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);

    nabto_coap_error err = nabto_coap_server_response_set_payload(request, cborResponse, used);
    if (err != NABTO_COAP_ERROR_OK) {
        // Dont try to add a payload on OOM it would propably fail
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(5,00), NULL);
    } else {
        // On errors we should still cleanup the request
        nabto_coap_server_response_ready(request);
    }
    nabto_coap_server_request_free(request);

}

struct nm_tcptunnel* find_tunnel(struct nm_tcptunnels* tunnels, const char* tid)
{
    if (tid == NULL) {
        return NULL;
    }
    struct nm_tcptunnel* iterator = tunnels->tunnelsSentinel.next;
    while(iterator != &tunnels->tunnelsSentinel) {
        if (strcmp(tid, iterator->tunnelId) == 0) {
            return iterator;
        }
        iterator = iterator->next;
    }
    return NULL;
}
