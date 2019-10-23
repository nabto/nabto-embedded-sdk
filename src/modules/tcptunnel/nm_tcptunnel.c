#include "nm_tcptunnel.h"
#include "nm_tcptunnel_connection.h"
#include "nm_tcptunnel_coap.h"

#include <core/nc_device.h>
#include <core/nc_stream_manager.h>
#include <platform/np_logging.h>
#include <platform/np_util.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_TUNNEL

static void nm_tcptunnel_stream_listener_callback(np_error_code ec, struct nc_stream_context* stream, void* data);

static void connection_event(uint64_t connectionRef, enum nc_connection_event event, void* data);

static void nm_tcptunnel_destroy(struct nm_tcptunnel* tunnel);

np_error_code nm_tcptunnels_init(struct nm_tcptunnels* tunnels, struct nc_device_context* device)
{
    if (tunnels->device != NULL) {
        return NABTO_EC_RESOURCE_EXISTS;
    }
    tunnels->device = device;
    tunnels->tunnelsSentinel.next = &tunnels->tunnelsSentinel;
    tunnels->tunnelsSentinel.prev = &tunnels->tunnelsSentinel;
    // TODO make it customizable.
    tunnels->defaultPort = 8080;
    tunnels->defaultHost.type = NABTO_IPV4;
    tunnels->defaultHost.ip.v4[0] = 0x7f;
    tunnels->defaultHost.ip.v4[1] = 0x00;
    tunnels->defaultHost.ip.v4[2] = 0x00;
    tunnels->defaultHost.ip.v4[3] = 0x01;

    nm_tcptunnel_coap_init(tunnels, &device->coapServer);

    nc_device_add_connection_events_listener(device, &tunnels->connectionEventsListener, &connection_event, tunnels);

    return NABTO_EC_OK;

}

void nm_tcptunnels_deinit(struct nm_tcptunnels* tunnels)
{
    nc_device_remove_connection_events_listener(tunnels->device, &tunnels->connectionEventsListener);

    while (tunnels->tunnelsSentinel.next != &tunnels->tunnelsSentinel) {
        struct nm_tcptunnel* tunnel = tunnels->tunnelsSentinel.next;
        // stop and remove tunnel from tunnels
        nm_tcptunnel_deinit(tunnel);
    }
}

void connection_event(uint64_t connectionRef, enum nc_connection_event event, void* data)
{
    struct nm_tcptunnels* tunnels = data;
    if (event == NC_CONNECTION_EVENT_CLOSED) {
        struct nm_tcptunnel* iterator = tunnels->tunnelsSentinel.next;
        while (iterator != &tunnels->tunnelsSentinel) {
            struct nm_tcptunnel* current = iterator;
            iterator = iterator->next;
            if (current->connectionRef == connectionRef) {
                nm_tcptunnel_deinit(current);
                nm_tcptunnel_destroy(current);
            }
        }
    }
}

struct nm_tcptunnel* nm_tcptunnel_create(struct nm_tcptunnels* tunnels)
{
    struct nm_tcptunnel* tunnel = calloc(1, sizeof(struct nm_tcptunnel));

    tunnel->tunnels = tunnels;
    tunnel->id = tunnels->idCounter;
    tunnels->idCounter++;

    tunnel->connectionsSentinel.next = &tunnel->connectionsSentinel;
    tunnel->connectionsSentinel.prev = &tunnel->connectionsSentinel;

    // insert into list of tunnels
    struct nm_tcptunnel* before = tunnels->tunnelsSentinel.prev;
    struct nm_tcptunnel* after = &tunnels->tunnelsSentinel;

    before->next = tunnel;
    tunnel->next = after;
    after->prev = tunnel;
    tunnel->prev = before;

    memset(tunnel->tunnelId, 0, 17);
    np_data_to_hex((uint8_t*)&(tunnel->id), 8, tunnel->tunnelId);
    tunnel->streamPort = 0; // initially zero
    return tunnel;
}

void nm_tcptunnel_destroy(struct nm_tcptunnel* tunnel)
{
    struct nm_tcptunnel* before = tunnel->prev;
    struct nm_tcptunnel* after = tunnel->next;
    before->next = after;
    after->prev = before;

    free(tunnel);
}

void nm_tcptunnel_init(struct nm_tcptunnel* tunnel, struct np_ip_address* address, uint16_t port)
{
    tunnel->address = *address;
    tunnel->port = port;
}

void nm_tcptunnel_deinit(struct nm_tcptunnel* tunnel)
{
    while(tunnel->connectionsSentinel.next != &tunnel->connectionsSentinel) {
        struct nm_tcptunnel_connection* connection = tunnel->connectionsSentinel.next;
        nm_tcptunnel_remove_connection(connection);
        nm_tcptunnel_connection_stop_from_manager(connection);
    }
    nc_stream_manager_remove_listener(&tunnel->streamListener);
}

np_error_code nm_tcptunnel_init_stream_listener(struct nm_tcptunnel* tunnel)
{
    struct nc_device_context* device = tunnel->tunnels->device;
    struct nc_stream_manager_context* streamManager = &device->streamManager;
    np_error_code ec;
    ec = nc_stream_manager_add_listener(streamManager, &tunnel->streamListener, tunnel->streamPort, &nm_tcptunnel_stream_listener_callback, tunnel);
    if (!ec) {
        tunnel->streamPort = tunnel->streamListener.type;
    }
    NABTO_LOG_TRACE(LOG, "Begin listening for streams on port %" PRIu32, tunnel->streamListener.type);
    return ec;
}

void nm_tcptunnel_stream_listener_callback(np_error_code ec, struct nc_stream_context* stream, void* data)
{
    if (ec) {
        // probably stopped
        return;
    } else {
        struct nm_tcptunnel* tunnel = data;
        struct nm_tcptunnel_connection* c = nm_tcptunnel_connection_new();
        np_error_code ec = nm_tcptunnel_connection_init(tunnel, c, stream);
        if(!ec) {
            nm_tcptunnel_connection_start(c);
        } else {
            nm_tcptunnel_connection_free(c);
        }
    }
}


/**
 * called from a connection when it detects that the connection is closed.
 */
void nm_tcptunnel_remove_connection(struct nm_tcptunnel_connection* connection)
{
    // remove connection from connections.
    struct nm_tcptunnel_connection* before = connection->prev;
    struct nm_tcptunnel_connection* after = connection->next;
    before->next = after;
    after->prev = before;

    connection->next = NULL;
    connection->prev = NULL;
}
