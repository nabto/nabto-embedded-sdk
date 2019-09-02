#include "nm_tcptunnel_coap.h"

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
 *   "Host": string
 *   "Port": integer
 * }
 */
void create_tunnel(struct nabto_coap_server_request* request, void* data)
{
    struct nm_tcptunnels* tunnels = data;
    // Read host and port, insert default if not exists.

    // Check IAM.

    // Create tunnel resource.

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
