#include "nc_client_connection_dispatch.h"
#include "nc_udp_dispatch.h"
#include "nc_connection.h"
#include "nc_device.h"

#include <platform/np_logging.h>
#include <platform/np_allocator.h>
#include <string.h>
#include <limits.h>

#define LOG NABTO_LOG_MODULE_CLIENT_CONNECTION_DISPATCH

static void nc_client_connection_dispatch_send_internal_error_cb(np_error_code ec, void* data);

np_error_code nc_client_connection_dispatch_init(struct nc_client_connection_dispatch_context* ctx,
                                        struct np_platform* pl,
                                        struct nc_device_context* dev)
{
    ctx->device = dev;
    ctx->connections = &dev->connections;
    ctx->closing = false;
    ctx->sendingInternalError = false;
    np_error_code ec = np_completion_event_init(&pl->eq, &ctx->sendCompletionEvent, &nc_client_connection_dispatch_send_internal_error_cb, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ctx->pl = pl;
    return NABTO_EC_OK;
}

void nc_client_connection_dispatch_deinit(struct nc_client_connection_dispatch_context* ctx)
{
    if (ctx->pl != NULL) { // if init called
        np_completion_event_deinit(&ctx->sendCompletionEvent);
    }
}

static void nc_client_connection_dispatch_send_internal_error_cb(np_error_code ec, void* data)
{
    (void)ec;
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
    if (bufferSize < 17) {
        return; // this is not a valid packet with atleast a nabto connection id header and a dtls packet type
    }
    uint8_t* id = NULL;
    id = buffer;

    struct nc_connection* connection = nc_connections_connection_from_id(ctx->connections, id);
    if (connection != NULL) {
        np_error_code ec;
        ec = nc_client_connection_handle_packet(ctx->pl, connection->connectionImplCtx, sock, ep, buffer, bufferSize);
        if (ec != NABTO_EC_OK) {
            //nc_client_connection_close_connection(&ctx->elms[i].conn);
        }
        return;
    }

    // if the packet is a dtls handshake packet it can be for a new connection.
    // 22 = handshake
    // 1 = client hello on position x maybe ~14
    // the first 16 bytes is the connection header
    if (buffer[16] == 22) {
        connection = nc_connections_alloc_client_connection(ctx->connections);
        if (!connection) {
            nc_client_connection_dispatch_send_internal_error(ctx, sock, ep, buffer, bufferSize);
            return;
        }
        NABTO_LOG_TRACE(LOG, "Open new connection");
        np_error_code ec = nc_client_connection_init(ctx->pl, connection->connectionImplCtx, ctx, ctx->device, sock, ep, buffer, bufferSize);
        if (ec == NABTO_EC_OK) {
            NABTO_LOG_INFO(LOG, "Client <-> Device connection: %" NABTO_LOG_PRIu64 " created.", connection->connectionRef);
            nc_client_connection_start(connection->connectionImplCtx, buffer, bufferSize);
        } else {
            NABTO_LOG_INFO(LOG, "Client <-> Device connection: %" NABTO_LOG_PRIu64 " initialization failed: %s.", connection->connectionRef, np_error_code_to_string(ec));
            nc_client_connection_dispatch_send_internal_error(ctx, sock, ep, buffer, bufferSize);
            nc_client_connection_destroy_connection(connection->connectionImplCtx);
        }
        return;
    }
}

np_error_code nc_client_connection_dispatch_close_connection(struct nc_client_connection_dispatch_context* ctx,
                                                             struct nc_client_connection* conn)
{
    nc_connections_free_connection(ctx->connections, conn->parent);

    return NABTO_EC_OK;
}

bool nc_client_connection_dispatch_validate_connection_id(struct nc_client_connection_dispatch_context* ctx, const uint8_t* connectionId)
{
    if (nc_connections_connection_from_id(ctx->connections, connectionId) != NULL) {
        return true;
    }
    return false;
}
