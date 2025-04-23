#include "nc_virtual_connection.h"

#include "nc_device.h"
#include <platform/np_allocator.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_VIRTUAL_CONNECTION

struct nc_connection* nc_virtual_connection_new(struct nc_device_context* device)
{
    struct nc_connection* conn = nc_connections_alloc_virtual_connection(&device->connections);
    if (conn != NULL) {
        struct nc_virtual_connection* virConn = conn->connectionImplCtx;
        virConn->parent = conn;
        nn_llist_init(&virConn->coapRequests);
        nc_connection_events_listener_notify(conn, NC_CONNECTION_EVENT_OPENED);
    }
    return conn;
}

void nc_virtual_connection_destroy(struct nc_virtual_connection* conn)
{
    nc_connection_events_listener_notify(conn->parent, NC_CONNECTION_EVENT_CLOSED);
    nc_coap_server_remove_connection(&conn->parent->device->coapServer, conn->parent);

    nn_llist_deinit(&conn->coapRequests);
    np_free(conn->clientFingerprint);
    np_free(conn->deviceFingerprint);
    nc_connections_free_connection(&conn->parent->device->connections, conn->parent);
}

bool nc_virtual_connection_add_coap_request(struct nc_virtual_connection* conn, struct nc_coap_server_request* request)
{
    (void)conn;
    nn_llist_append(&conn->coapRequests, &request->virRequest->listElm, request);
    return true;
}

bool nc_virtual_connection_remove_coap_request(struct nc_virtual_connection* conn, struct nc_coap_server_request* request)
{
    (void)conn;
    nn_llist_erase_node(&request->virRequest->listElm);
    return true;
}


void nc_virtual_connection_close(struct nc_virtual_connection* conn)
{
    // TODO: does this do anything?
}

np_error_code nc_virtual_connection_set_client_fingerprint(struct nc_virtual_connection* conn, uint8_t* fp)
{
    np_free(conn->clientFingerprint);
    conn->clientFingerprint = np_calloc(1, 32);
    if (conn->clientFingerprint == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    memcpy(conn->clientFingerprint, fp, 32);
    return NABTO_EC_OK;
}

np_error_code nc_virtual_connection_set_device_fingerprint(struct nc_virtual_connection* conn, uint8_t* fp)
{
    np_free(conn->deviceFingerprint);
    conn->deviceFingerprint = np_calloc(1, 32);
    if (conn->deviceFingerprint == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    memcpy(conn->deviceFingerprint, fp, 32);
    return NABTO_EC_OK;
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
