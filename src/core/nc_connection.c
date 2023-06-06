#include "nc_connection.h"
#include "nc_virtual_connection.h"
#include <platform/np_logging.h>
#include <platform/np_allocator.h>
#include "nc_device.h"

#define LOG NABTO_LOG_MODULE_CONNECTION

np_error_code nc_connections_init(struct nc_connections_context* ctx, struct nc_device_context* device)
{
    nn_llist_init(&ctx->connections);
    ctx->maxConcurrentConnections = SIZE_MAX;
    ctx->closing = false;
    ctx->device = device;
    return NABTO_EC_OK;
}

void nc_connections_deinit(struct nc_connections_context* ctx)
{
    struct nc_connection* connection;
    struct nn_llist_iterator it = nn_llist_begin(&ctx->connections);
    while(!nn_llist_is_end(&it)) {
        connection = nn_llist_get_item(&it);
        nn_llist_next(&it);

        //destroy connection calls close connection which alters the list
        if (!connection->isVirtual) {
            nc_client_connection_destroy_connection(connection->connectionImplCtx);
        } else {
            nc_virtual_connection_destroy(connection->connectionImplCtx);
        }
    }
}

np_error_code nc_connections_async_close(struct nc_connections_context* ctx, nc_connections_close_callback cb, void* data)
{
    bool hasActive = false;
    ctx->closing = true;
    struct nc_connection* connection;
    NN_LLIST_FOREACH(connection, &ctx->connections) {
        if (!connection->isVirtual) {
            nc_client_connection_close_connection(connection->connectionImplCtx);
            hasActive = true;
        } else {
            nc_virtual_connection_close(connection->connectionImplCtx);
        }
    }

    if (!hasActive) {
        return NABTO_EC_STOPPED;
    } else {
        ctx->closeCb = cb;
        ctx->closeData = data;
        return NABTO_EC_OK;
    }

}

struct nc_connection* nc_connections_alloc_client_connection(struct nc_connections_context* ctx)
{
    if (ctx->currentConnections >= ctx->maxConcurrentConnections) {
        NABTO_LOG_INFO(LOG, "Cannot allocate more client connections, the limit has been reached");
        return NULL;
    }
    struct nc_connection* connection = (struct nc_connection*)np_calloc(1, sizeof(struct nc_connection));
    struct nc_client_connection* cliConn = (struct nc_client_connection*)np_calloc(1, sizeof(struct nc_client_connection));
    if (connection == NULL || cliConn == NULL) {
        NABTO_LOG_INFO(LOG, "Cannot create connection as system is out of memory.");
        np_free(connection);
        np_free(cliConn);
        return NULL;
    }
    nc_connection_init(connection, ctx->device, false, cliConn);
    ctx->currentConnections++;
    nn_llist_append(&ctx->connections, &connection->connectionsNode, connection);
    return connection;
}

struct nc_connection* nc_connections_alloc_virtual_connection(struct nc_connections_context* ctx)
{
    if (ctx->currentConnections >= ctx->maxConcurrentConnections) {
        NABTO_LOG_INFO(LOG, "Cannot allocate more client connections, the limit has been reached");
        return NULL;
    }
    struct nc_connection* connection = (struct nc_connection*)np_calloc(1, sizeof(struct nc_connection));
    struct nc_virtual_connection* virConn = (struct nc_virtual_connection*)np_calloc(1, sizeof(struct nc_virtual_connection));
    if (connection == NULL || virConn == NULL) {
        NABTO_LOG_INFO(LOG, "Cannot create virtual connection as system is out of memory.");
        np_free(connection);
        np_free(virConn);
        return NULL;
    }
    nc_connection_init(connection, ctx->device, true, virConn);
    ctx->currentConnections++;
    nn_llist_append(&ctx->connections, &connection->connectionsNode, connection);
    return connection;
}

void nc_connections_free_connection(struct nc_connections_context* ctx, struct nc_connection* connection)
{
    nn_llist_erase_node(&connection->connectionsNode);
    np_free(connection->connectionImplCtx);
    np_free(connection);
    ctx->currentConnections--;
    if (ctx->closing && ctx->currentConnections <= 0) {
        nc_connections_close_callback cb = ctx->closeCb;
        ctx->closeCb = NULL;
        if (cb) {
            cb(ctx->closeData);
        }
    }
}

struct nc_connection* nc_connections_connection_from_ref(struct nc_connections_context* ctx, uint64_t ref)
{
    struct nc_connection* connection;
    NN_LLIST_FOREACH(connection, &ctx->connections) {
        if (connection->connectionRef == ref) {
            return connection;
        }
    }
    return NULL;
}

struct nc_connection* nc_connections_connection_from_client_connection(struct nc_connections_context* ctx, struct nc_client_connection* cliConn)
{
    struct nc_connection* connection;
    NN_LLIST_FOREACH(connection, &ctx->connections) {
        if (!connection->isVirtual && connection->connectionImplCtx == cliConn) {
            return connection;
        }
    }
    return NULL;

}

struct nc_connection* nc_connections_connection_from_id(struct nc_connections_context* ctx, const uint8_t* id)
{
    struct nc_connection* connection;
    NN_LLIST_FOREACH(connection, &ctx->connections) {
        // compare middle 14 bytes, ignoring the channel ID and protocol prefix
        if (!connection->isVirtual) {
            struct nc_client_connection* cliConn = connection->connectionImplCtx;
            if (memcmp(id+1, cliConn->id.id+1, 14) == 0) {
                return connection;
            }
        }
    }
    return NULL;
}

size_t nc_connections_count_connections(struct nc_connections_context* ctx)
{
    return ctx->currentConnections;
}




np_error_code nc_connection_init(struct nc_connection* conn, struct nc_device_context* device, bool isVirtual, void* impl)
{
    np_error_code ec;
    memset(conn, 0, sizeof(struct nc_connection));
    conn->device = device;
    conn->isVirtual = isVirtual;
    conn->connectionImplCtx = impl;
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    conn->hasSpake2Key = false;
    conn->passwordAuthenticated = false;
#endif
    ec = nc_device_next_connection_ref(device, &conn->connectionRef);
    return ec;
}


bool nc_connection_get_client_fingerprint(struct nc_connection* connection, uint8_t* fp)
{
    if (connection->isVirtual) {
        return nc_virtual_connection_get_client_fingerprint(connection->connectionImplCtx, fp);
    } else {
        return nc_client_connection_get_client_fingerprint(connection->connectionImplCtx, fp);
    }
}

bool nc_connection_get_device_fingerprint(struct nc_connection* connection, uint8_t* fp)
{
    if (connection->isVirtual) {
        return nc_virtual_connection_get_device_fingerprint(connection->connectionImplCtx, fp);
    } else {
        memcpy(fp, connection->device->fingerprint, 32);
        return true;
    }

}

bool nc_connection_is_local(struct nc_connection* connection)
{
    if (connection->isVirtual) {
        // TODO: can a virtual connection be local?
        return false;
    } else {
        struct nc_client_connection* conn = connection->connectionImplCtx;
        return (&conn->device->localUdp == conn->currentChannel.sock);
    }
}

#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
bool nc_connection_is_password_authenticated(struct nc_connection* connection)
{
    return connection->passwordAuthenticated;
}
#endif

bool nc_connection_is_virtual(struct nc_connection* connection)
{
    return connection->isVirtual;
}


void nc_connection_events_listener_notify(struct nc_connection* conn, enum nc_connection_event event)
{
    nc_device_connection_events_listener_notify(conn->device, conn->connectionRef, event);
}
