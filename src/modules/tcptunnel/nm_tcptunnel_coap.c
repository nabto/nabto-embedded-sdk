#include "nm_tcptunnel.h"
#include "nm_tcptunnel_coap.h"

#include <core/nc_coap_server.h>
#include <core/nc_iam.h>

static void create_tunnel(struct nabto_coap_server_request* request, void* data);
static void delete_tunnel(struct nabto_coap_server_request* request, void* data);
static void get_tunnel(struct nabto_coap_server_request* request, void* data);
static void list_tunnels(struct nabto_coap_server_request* request, void* data);
static void list_connections(struct nabto_coap_server_request* request, void* data);
static void get_connection(struct nabto_coap_server_request* request, void* data);

void nm_tcptunnel_coap_init(struct nm_tcptunnels* tunnels, struct nabto_coap_server* server)
{
    nabto_coap_server_add_resource(server, NABTO_COAP_CODE_POST,
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
    tunnel->address = address;
    tunnel->port = port;




    // Return 201 Created.
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
