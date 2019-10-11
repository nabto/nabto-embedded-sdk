#include "nc_client_connection_dispatch.h"

#include <platform/np_logging.h>
#include <string.h>

#define LOG NABTO_LOG_MODULE_CLIENT_CONNECTION_DISPATCH

//struct nc_client_connect_dispatch_context ctx;

void nc_client_connection_dispatch_init(struct nc_client_connection_dispatch_context* ctx,
                                        struct np_platform* pl,
                                        struct nc_device_context* dev)
{
    int i = 0;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        memset(&ctx->elms[i].conn, 0, sizeof(struct nc_client_connection));
        ctx->elms[i].active = false;
    }
    ctx->device = dev;
    ctx->pl = pl;
    ctx->closing = false;
}

void nc_client_connection_dispatch_deinit(struct nc_client_connection_dispatch_context* ctx)
{
    int i = 0;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if (ctx->elms[i].active) {
            nc_client_connection_destroy_connection(&ctx->elms[i].conn);
            ctx->elms[i].active = false;
        }
    }
}

void nc_client_connection_dispatch_try_close(struct nc_client_connection_dispatch_context* ctx)
{
    bool allClosed = true;
    int i = 0;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if (ctx->elms[i].active) {
            allClosed = false;
            break;
        }
    }
    if (allClosed && ctx->closeCb) {
        ctx->closeCb(ctx->closeData);
    }
}

np_error_code nc_client_connection_dispatch_async_close(struct nc_client_connection_dispatch_context* ctx, nc_client_connection_dispatch_close_callback cb, void* data)
{
    ctx->closing = true;
    bool hasActive = false;
    int i = 0;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if (ctx->elms[i].active) {
            nc_client_connection_close_connection(&ctx->elms[i].conn);
            hasActive = true;
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

/*//void nc_client_connect_dispatch_handle_packet(const np_error_code ec, struct np_udp_endpoint ep,
//                                              np_communication_buffer* buffer, uint16_t bufferSize,
//                                              void* data)*/
void nc_client_connection_dispatch_handle_packet(struct nc_client_connection_dispatch_context* ctx,
                                                 struct nc_udp_dispatch_context* sock, struct np_udp_endpoint ep,
                                                 uint8_t* buffer, uint16_t bufferSize)
{
    int i;
    uint8_t* id;
    id = buffer;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        // compare middle 14 bytes, ignoring the channel ID and protocol prefix
        if (ctx->elms[i].active && memcmp(id+1, ctx->elms[i].conn.id.id+1, 14) == 0) {
            np_error_code ec;
            ec = nc_client_connection_handle_packet(ctx->pl, &ctx->elms[i].conn, sock, ep, buffer, bufferSize);
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
        for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
            if(!ctx->elms[i].active) {
                np_error_code ec = nc_client_connection_open(ctx->pl, &ctx->elms[i].conn, ctx, ctx->device, sock, ep, buffer, bufferSize);
                if (ec == NABTO_EC_OK) {
                    ctx->elms[i].active = true;
                }
                return;
            }
        }
    }
}

np_error_code nc_client_connection_dispatch_close_connection(struct nc_client_connection_dispatch_context* ctx,
                                                             struct nc_client_connection* conn)
{
    int i;
    for (i = 0; i<NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if (conn == &ctx->elms[i].conn) {
            ctx->elms[i].active = false;
        }
    }
    if (ctx->closing) {
        nc_client_connection_dispatch_try_close(ctx);
    }
    return NABTO_EC_OK;
}


struct nc_client_connection* nc_client_connection_dispatch_connection_from_ref(struct nc_client_connection_dispatch_context* ctx, uint64_t ref)
{
    int i;
    for (i = 0; i<NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if (ctx->elms[i].active && ctx->elms[i].conn.connectionRef == ref) {
            return &ctx->elms[i].conn;
        }
    }
    return NULL;
}


bool nc_client_connection_dispatch_user_in_use(struct nc_client_connection_dispatch_context* ctx, struct nc_iam_user* user)
{
    int i;
    for (i = 0; i<NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if (ctx->elms[i].active && ctx->elms[i].conn.user == user) {
            return true;
        }
    }
    return false;
}
