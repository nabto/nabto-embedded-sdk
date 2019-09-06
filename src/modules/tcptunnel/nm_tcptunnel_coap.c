#include "nm_tcptunnel.h"
#include "nm_tcptunnel_coap.h"

#include <core/nc_coap_server.h>
#include <core/nc_iam.h>

#include <cbor.h>

static void create_tunnel(struct nabto_coap_server_request* request, void* data);
static void delete_tunnel(struct nabto_coap_server_request* request, void* data);
static void get_tunnel(struct nabto_coap_server_request* request, void* data);
static void list_tunnels(struct nabto_coap_server_request* request, void* data);
static void list_connections(struct nabto_coap_server_request* request, void* data);
static void get_connection(struct nabto_coap_server_request* request, void* data);

void nm_tcptunnel_coap_init(struct nm_tcptunnels* tunnels, struct nc_coap_server_context* server)
{
    nabto_coap_server_add_resource(&server->server, NABTO_COAP_CODE_POST,
                                   (const char*[]){"tcptunnels", NULL},
                                   create_tunnel, tunnels);
}

/**
 * Create a tunnel.
 *
 * Request format
 * {
 *   "IpV4": hexstring
 *   "IpV6": hexstring
 *   "Port": integer
 * }
 */
void create_tunnel(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;
    // Read host and port, insert default if not exists.

    // TODO implement read ip and port.

    struct np_ip_address address = tunnels->defaultHost;
    uint16_t port = tunnels->defaultPort;

    struct nc_iam_attributes attributes;
    memset(&attributes, 0, sizeof(struct nc_iam_attributes));

    np_error_code ec;

    ec = nc_iam_attributes_add_number(&attributes, "TcpTunnel:Port", port);
    if (ec) {
        // TODO send error 500
    }
    ec = nc_iam_attributes_add_string(&attributes, "TcpTunnel:Host", np_ip_address_to_string(&address));
    if (ec) {
        // TODO send error 500
    }

    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    // Check IAM.
    ec = nc_iam_check_access_attributes(connection, "TcpTunnel:Create", &attributes);
    if (ec) {
        // TODO return 403
    }

    // the user has access to create the tunnel

    // Create tunnel resource.
    struct nm_tcptunnel* tunnel = nm_tcptunnel_create(tunnels);
    nm_tcptunnel_init(tunnel, &address, port);
    nm_tcptunnel_init_stream_listener(tunnel);

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

    // Return 201 Created.
    struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
    nabto_coap_server_response_set_code(response, NABTO_COAP_CODE(2,01));
    nabto_coap_server_response_set_content_format(response, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_coap_server_response_set_payload(response, cborResponse, used);
    nabto_coap_server_response_ready(response);
}

void delete_tunnel(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;
}

void get_tunnel(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;
}

void list_tunnels(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;
}

void list_connections(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;
}

void get_connection(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;
}
