#include "nc_virtual_connection.h"

#include <platform/np_logging.h>
#include <platform/np_allocator.h>
#include "nc_device.h"

#define LOG NABTO_LOG_MODULE_VIRTUAL_CONNECTION

struct nc_connection* nc_virtual_connection_new(struct nc_device_context* device)
{
    struct nc_connection* conn = nc_connections_alloc_virtual_connection(&device->connections);
    if (conn != NULL) {
        struct nc_virtual_connection* virConn = conn->connectionImplCtx;
        virConn->parent = conn;
        nc_connection_events_listener_notify(conn, NC_CONNECTION_EVENT_OPENED);
    }
    return conn;
}

void nc_virtual_connection_destroy(struct nc_virtual_connection* conn)
{
    nc_connection_events_listener_notify(conn->parent, NC_CONNECTION_EVENT_CLOSED);
    nc_coap_server_remove_connection(&conn->parent->device->coapServer, conn);
    np_free(conn->clientFingerprint);
    np_free(conn->deviceFingerprint);
    nc_connections_free_connection(&conn->parent->device->connections, conn->parent);
}

void nc_virtual_connection_close(struct nc_virtual_connection* conn)
{
    // TODO: does this do anything?
}

bool nc_virtual_connection_set_client_fingerprint(struct nc_virtual_connection* conn, uint8_t* fp)
{
    np_free(conn->clientFingerprint);
    conn->clientFingerprint = np_calloc(1, 32);
    if (conn->clientFingerprint == NULL) {
        return false;
    }
    memcpy(conn->clientFingerprint, fp, 32);
    return true;
}

bool nc_virtual_connection_set_device_fingerprint(struct nc_virtual_connection* conn, uint8_t* fp)
{
    np_free(conn->deviceFingerprint);
    conn->deviceFingerprint = np_calloc(1, 32);
    if (conn->deviceFingerprint == NULL) {
        return false;
    }
    memcpy(conn->deviceFingerprint, fp, 32);
    return true;
}


bool nc_virtual_connection_get_client_fingerprint(struct nc_virtual_connection* conn, uint8_t* fp)
{
    if (conn->clientFingerprint != NULL) {
        memcpy(fp, conn->clientFingerprint, 32);
        return true;
    }
    return false;
}

bool nc_virtual_connection_get_device_fingerprint(struct nc_virtual_connection* conn, uint8_t* fp)
{
    if (conn->deviceFingerprint != NULL) {
        memcpy(fp, conn->deviceFingerprint, 32);
        return true;
    }
    return false;
}
