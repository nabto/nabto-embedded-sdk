#include "nm_tcptunnel.h"
#include "nm_tcptunnel_coap.h"

#include <core/nc_coap_server.h>
#include <core/nc_iam.h>
#include <platform/np_logging.h>

#include <cbor.h>

#define LOG NABTO_LOG_MODULE_TUNNEL

static void create_tunnel(struct nabto_coap_server_request* request, void* data);
static void delete_tunnel(struct nabto_coap_server_request* request, void* data);
static void get_tunnel(struct nabto_coap_server_request* request, void* data);

static struct nm_tcptunnel* find_tunnel(struct nm_tcptunnels* tunnels, const char* tid);

void nm_tcptunnel_coap_init(struct nm_tcptunnels* tunnels, struct nc_coap_server_context* server)
{
    nabto_coap_server_add_resource(&server->server, NABTO_COAP_CODE_POST,
                                   (const char*[]){"tcptunnels", NULL},
                                   create_tunnel, tunnels);
    nabto_coap_server_add_resource(&server->server, NABTO_COAP_CODE_DELETE,
                                   (const char*[]){"tcptunnels", "{tid}", NULL},
                                   delete_tunnel, tunnels);
    nabto_coap_server_add_resource(&server->server, NABTO_COAP_CODE_GET,
                                   (const char*[]){"tcptunnels", "{tid}", NULL},
                                   get_tunnel, tunnels);
}

bool parse_host_and_port(struct nabto_coap_server_request* request, struct nm_tcptunnels* tunnels, struct np_ip_address* address, uint16_t* port)
{
    *address = tunnels->defaultHost;
    *port = tunnels->defaultPort;

    int32_t contentFormat;
    contentFormat = nabto_coap_server_request_get_content_format(request);

    if (contentFormat != NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        return false;
    }

    void* payload;
    size_t payloadLength;
    if (!nabto_coap_server_request_get_payload(request, &payload, &payloadLength)) {
        // no payload, ok
        return true;
    }

    CborParser parser;
    CborValue map;
    if (cbor_parser_init(payload, payloadLength, 0, &parser, &map) != CborNoError) {
        return false;
    }

    if (!cbor_value_is_map(&map)) {
        return false;
    }

    CborValue ip;
    size_t length = 0;
    if (cbor_value_map_find_value(&map, "Ip", &ip) == CborNoError &&
        cbor_value_is_byte_string(&ip) &&
        cbor_value_get_string_length(&ip, &length) == CborNoError)
    {
        if (length == 4) {
            address->type = NABTO_IPV4;
            if (cbor_value_copy_byte_string(&ip, address->ip.v4, &length, NULL) != CborNoError) {
                return false;
            }
        } else if(length == 16) {
            address->type = NABTO_IPV6;
            if (cbor_value_copy_byte_string(&ip, address->ip.v6, &length, NULL) != CborNoError) {
                return false;
            }
        } else {
            // ip not read
        }

    }

    CborValue value;
    uint64_t p;
    if (cbor_value_map_find_value(&map, "Port", &value) == CborNoError &&
        cbor_value_is_unsigned_integer(&value))
    {
        if (cbor_value_get_uint64(&value, &p) != CborNoError)  {
            return false;
        }
        *port = (uint16_t)p;
    }

    return true;
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
    np_error_code ec;
    struct np_ip_address address;
    uint16_t port;

    if (!parse_host_and_port(request, tunnels, &address, &port)) {
        nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(4,00), NULL);
        return;
    }

    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    {
        uint8_t cborAttributes[128];
        CborEncoder encoder;
        CborEncoder map;
        cbor_encoder_init(&encoder, cborAttributes, 128, 0);
        cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

        cbor_encode_text_stringz(&map, "TcpTunnel:Port");
        cbor_encode_int(&map, port);
        cbor_encode_text_stringz(&map, "TcpTunnel:Host");
        cbor_encode_text_stringz(&map, np_ip_address_to_string(&address));
        cbor_encoder_close_container(&encoder, &map);

        size_t used = cbor_encoder_get_buffer_size(&encoder, cborAttributes);

        // Check IAM.
        ec = nc_iam_check_access(connection, "TcpTunnel:Create", cborAttributes, used);
        if (ec) {
            nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(4,03), NULL);
            return;
        }
    }

    // the user has access to create the tunnel
    {
        // Create tunnel resource.
        struct nm_tcptunnel* tunnel = nm_tcptunnel_create(tunnels);
        nm_tcptunnel_init(tunnel, &address, port);
        nm_tcptunnel_init_stream_listener(tunnel);

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
            // Not possible!
            // TODO send error 500
            // TODO cleanup tunnel
        }
        size_t used = cbor_encoder_get_buffer_size(&encoder, cborResponse);

        NABTO_LOG_INFO(LOG, "Created tcp tunnel. destination %s:%" PRIu16, np_ip_address_to_string(&address), port);
        // Return 201 Created.
        struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
        nabto_coap_server_response_set_code(response, NABTO_COAP_CODE(2,01));
        nabto_coap_server_response_set_content_format(response, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        nabto_coap_server_response_set_payload(response, cborResponse, used);
        nabto_coap_server_response_ready(response);
    }
}

/**
 * CoAP DELETE /tunnels/:tid
 */
void delete_tunnel(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;

    struct nm_tcptunnel* tunnel = find_tunnel(tunnels, nabto_coap_server_request_get_parameter(request, "tid"));
    if (tunnel == NULL) {
        nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(4,04), NULL);
        return;
    }

    np_error_code ec;

    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    if (tunnel->connectionRef != connection->connectionRef) {
        nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(4,03), NULL);
        return;
    }

    // Check IAM.
    ec = nc_iam_check_access(connection, "TcpTunnel:Delete", NULL, 0);
    if (ec) {
        nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(4,03), NULL);
        return;
    }

    nm_tcptunnel_deinit(tunnel);

    struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
    nabto_coap_server_response_set_code(response, NABTO_COAP_CODE(2,02));
    nabto_coap_server_response_ready(response);
}

void get_tunnel(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;
    struct nm_tcptunnel* tunnel = find_tunnel(tunnels, nabto_coap_server_request_get_parameter(request, "tid"));
    if (tunnel == NULL) {
        nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(4,04), NULL);
        return;
    }

    struct nc_iam_attributes attributes;
    memset(&attributes, 0, sizeof(struct nc_iam_attributes));

    np_error_code ec;

    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);
    if (tunnel->connectionRef != connection->connectionRef) {
        nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(4,03), NULL);
        return;
    }

    // Check IAM.
    ec = nc_iam_check_access(connection, "TcpTunnel:Get", NULL, 0);
    if (ec) {
        nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(4,03), NULL);
        return;
    }

    uint8_t cborResponse[128];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, cborResponse, 128, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    cbor_encode_text_stringz(&map, "StreamPort");
    cbor_encode_uint(&map, tunnel->streamPort);
    if (tunnel->address.type == NABTO_IPV4 || tunnel->address.type == NABTO_IPV6) {
        cbor_encode_text_stringz(&map, "Ip");
        if (tunnel->address.type == NABTO_IPV4) {
            cbor_encode_byte_string(&map, tunnel->address.ip.v4, 4);
        } else {
            cbor_encode_byte_string(&map, tunnel->address.ip.v6, 16);
        }
    }
    cbor_encode_text_stringz(&map, "Port");
    cbor_encode_uint(&map, tunnel->port);
    cbor_encoder_close_container(&encoder, &map);
    size_t extra = cbor_encoder_get_extra_bytes_needed(&encoder);
    if (extra != 0) {
        // Not possible!
        // TODO send error 500
        // TODO cleanup tunnel
    }
    size_t used = cbor_encoder_get_buffer_size(&encoder, cborResponse);

    // Return 201 Created.
    struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
    nabto_coap_server_response_set_code(response, NABTO_COAP_CODE(2,05));
    nabto_coap_server_response_set_content_format(response, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_coap_server_response_set_payload(response, cborResponse, used);
    nabto_coap_server_response_ready(response);

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
