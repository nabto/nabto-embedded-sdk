#include "nc_client_connection_dispatch.h"
#include "nc_udp_dispatch.h"

#include <platform/np_logging.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#define LOG NABTO_LOG_MODULE_CLIENT_CONNECTION_DISPATCH

static void nc_client_connection_dispatch_send_internal_error_cb(np_error_code ec, void* data);

void nc_client_connection_dispatch_init(struct nc_client_connection_dispatch_context* ctx,
                                        struct np_platform* pl,
                                        struct nc_device_context* dev)
{
    nn_llist_init(&ctx->connections);
    ctx->maxConcurrentConnections = SIZE_MAX;
    ctx->device = dev;
    ctx->pl = pl;
    ctx->closing = false;
    ctx->sendingInternalError = false;
    np_error_code ec = np_completion_event_init(&pl->eq, &ctx->sendCompletionEvent, &nc_client_connection_dispatch_send_internal_error_cb, ctx);
    if (ec != NABTO_EC_OK) {
        // todo
        //return ec;
    }

}

void nc_client_connection_dispatch_deinit(struct nc_client_connection_dispatch_context* ctx)
{
    if (ctx->pl != NULL) { // if init called

        //destroy connection calls close connection which alters the list

        struct nc_client_connection* connection;
        struct nn_llist_iterator it = nn_llist_begin(&ctx->connections);
        while(!nn_llist_is_end(&it)) {
            connection = nn_llist_get_item(&it);
            nn_llist_next(&it);

            nc_client_connection_destroy_connection(connection);
        }
    }
    np_completion_event_deinit(&ctx->sendCompletionEvent);
}

void nc_client_connection_dispatch_try_close(struct nc_client_connection_dispatch_context* ctx)
{
    if (ctx->currentConnections != 0) {
        return;
    }
    nc_client_connection_dispatch_close_callback cb = ctx->closeCb;
    ctx->closeCb = NULL;
    if (cb) {
        cb(ctx->closeData);
    }
}

np_error_code nc_client_connection_dispatch_async_close(struct nc_client_connection_dispatch_context* ctx, nc_client_connection_dispatch_close_callback cb, void* data)
{
    ctx->closing = true;
    bool hasActive = false;

    struct nc_client_connection* connection;
    NN_LLIST_FOREACH(connection, &ctx->connections) {
        nc_client_connection_close_connection(connection);
        hasActive = true;
    }

    if (!hasActive) {
        return NABTO_EC_STOPPED;
    } else {
        ctx->closeCb = cb;
        ctx->closeData = data;
        return NABTO_EC_OK;
    }
}

struct nc_client_connection* nc_client_connection_dispatch_alloc_connection(struct nc_client_connection_dispatch_context* ctx)
{
    if (ctx->currentConnections >= ctx->maxConcurrentConnections) {
        NABTO_LOG_INFO(LOG, "Cannot allocate more client connections, the limit has been reached");
        return NULL;
    }

    struct nc_client_connection* connection = (struct nc_client_connection*)calloc(1, sizeof(struct nc_client_connection));
    if (connection == NULL) {
        NABTO_LOG_INFO(LOG, "Cannot create connection as system is out of memory.");
        return NULL;
    }
    ctx->currentConnections++;
    return connection;
}

void nc_client_connection_dispatch_free_connection(struct nc_client_connection_dispatch_context* ctx, struct nc_client_connection* connection)
{
    free(connection);
    ctx->currentConnections--;
}

static void nc_client_connection_dispatch_send_internal_error_cb(np_error_code ec, void* data)
{
    struct nc_client_connection_dispatch_context* ctx = (struct nc_client_connection_dispatch_context*)data;
    ctx->sendingInternalError = false;
}


void nc_client_connection_dispatch_send_internal_error(struct nc_client_connection_dispatch_context *ctx,
                                                       struct nc_udp_dispatch_context *sock, struct np_udp_endpoint *ep,
                                                       uint8_t *buffer, uint16_t bufferSize)
{
    if (ctx->sendingInternalError) {
        return;
    }
    if (bufferSize < 16) {
        return;
    }
    static uint8_t responseBuffer[16+13+2];
    uint8_t* ptr = responseBuffer;
    // the following section constructs a dtls alert message saying internal error
    memcpy(ptr, buffer, 16); ptr += 16;
    *ptr = 21; ptr++; // alert content type
    *ptr = 0xfe; ptr++; // version major
    *ptr = 0xfd; ptr++; // version minor
    for (size_t i = 0; i < 8; i++) {
        *ptr = 0; ptr++; // epoch and sequence number
    }
    *ptr = 0; ptr++; // size
    *ptr = 2; ptr++;
    *ptr = 2; ptr++; // fatal alert
    *ptr = 80; ptr++; // internal_error message

    ctx->sendingInternalError = true;
    nc_udp_dispatch_async_send_to(sock, ep,
                                      responseBuffer, sizeof(responseBuffer),
                                      &ctx->sendCompletionEvent);
}

/*//void nc_client_connect_dispatch_handle_packet(const np_error_code ec, struct np_udp_endpoint ep,
//                                              np_communication_buffer* buffer, uint16_t bufferSize,
//                                              void* data)*/
void nc_client_connection_dispatch_handle_packet(struct nc_client_connection_dispatch_context* ctx,
                                                 struct nc_udp_dispatch_context* sock, struct np_udp_endpoint* ep,
                                                 uint8_t* buffer, uint16_t bufferSize)
{
    uint8_t* id;
    id = buffer;
    struct nc_client_connection* connection;
    NN_LLIST_FOREACH(connection, &ctx->connections) {
        // compare middle 14 bytes, ignoring the channel ID and protocol prefix
        if (memcmp(id+1, connection->id.id+1, 14) == 0) {
            np_error_code ec;
            ec = nc_client_connection_handle_packet(ctx->pl, connection, sock, ep, buffer, bufferSize);
            if (ec != NABTO_EC_OK) {
                //nc_client_connection_close_connection(&ctx->elms[i].conn);
            }
            return;
        }
    }

    // if the packet is a dtls handshake packet it can be for a new connection.
    // 22 = handshake
    // 1 = client hello on position x maybe ~14
    // the first 16 bytes is the connection header
    if (buffer[16] == 22) {
        struct nc_client_connection* connection = nc_client_connection_dispatch_alloc_connection(ctx);
        if (!connection) {
            nc_client_connection_dispatch_send_internal_error(ctx, sock, ep, buffer, bufferSize);
            return;
        }
        NABTO_LOG_TRACE(LOG, "Open new connection");
        np_error_code ec = nc_client_connection_open(ctx->pl, connection, ctx, ctx->device, sock, ep, buffer, bufferSize);
        if (ec == NABTO_EC_OK) {
            nn_llist_append(&ctx->connections, &connection->connectionsNode, connection);
        } else {
            nc_client_connection_dispatch_free_connection(ctx, connection);
        }
        return;
    }
}

np_error_code nc_client_connection_dispatch_close_connection(struct nc_client_connection_dispatch_context* ctx,
                                                             struct nc_client_connection* conn)
{
    nn_llist_erase_node(&conn->connectionsNode);
    nc_client_connection_dispatch_free_connection(ctx, conn);

    if (ctx->closing) {
        nc_client_connection_dispatch_try_close(ctx);
    }

    return NABTO_EC_OK;
}


struct nc_client_connection* nc_client_connection_dispatch_connection_from_ref(struct nc_client_connection_dispatch_context* ctx, uint64_t ref)
{
    struct nc_client_connection* connection;
    NN_LLIST_FOREACH(connection, &ctx->connections) {
        if (connection->connectionRef == ref) {
            return connection;
        }
    }
    return NULL;
}

bool nc_client_connection_dispatch_validate_connection_id(struct nc_client_connection_dispatch_context* ctx, const uint8_t* connectionId)
{
    struct nc_client_connection* connection;
    NN_LLIST_FOREACH(connection, &ctx->connections) {
        if (memcmp(connection->id.id+1, connectionId, 14) == 0) {
            return true;
        }
    }
    return false;
}
