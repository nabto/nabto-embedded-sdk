#include "nc_client_connect_dispatch.h"

#include <platform/np_logging.h>
#include <string.h>

#define LOG NABTO_LOG_MODULE_CLIENT_CONNECT_DISPATCH

struct nc_client_connect_dispatch_element {
    struct nc_client_connection conn;
    bool active;
};

struct nc_client_connect_dispatch_context {
    struct nc_stream_manager_context* streamManager;
    struct nc_client_connect_dispatch_element elms[NABTO_MAX_CLIENT_CONNECTIONS];
};

struct nc_client_connect_dispatch_context ctx;

void nc_client_connect_dispatch_init(struct np_platform* pl, struct nc_stream_manager_context* streamManager)
{
    int i = 0;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        memset(&ctx.elms[i].conn, 0, sizeof(struct nc_client_connection));
        ctx.elms[i].active = false;
    }
    ctx.streamManager = streamManager;
}

void nc_client_connect_dispatch_handle_packet(struct np_platform* pl, const np_error_code ec,
                                              struct np_udp_socket* sock, struct np_udp_endpoint ep,
                                              np_communication_buffer* buffer, uint16_t bufferSize)
{
    int i;
    uint8_t* id;
    if (ec != NABTO_EC_OK) {
        // We don't know which connection used the broken socket, so we just ignore errors here
        // Client connection will discover the broken channel at next usage
        return;
    }
    id = pl->buf.start(buffer);
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        // compare first 15 bytes, ignoring the channel ID
        if (ctx.elms[i].active && memcmp(id, ctx.elms[i].conn.id.id, 15) == 0) { 
            np_error_code ec;
            NABTO_LOG_INFO(LOG, "Found existing connection for new packet");
            ec = nc_client_connect_handle_packet(pl, &ctx.elms[i].conn, sock, ep, buffer, bufferSize);
            if (ec != NABTO_EC_OK) {
                nc_client_connect_dispatch_close_connection(pl, &ctx.elms[i].conn);
            }
            return;
        }
    }
    NABTO_LOG_INFO(LOG, "Found packet for new connection");
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if(!ctx.elms[i].active) {
            np_error_code ec = nc_client_connect_open(pl, &ctx.elms[i].conn, ctx.streamManager, sock, ep, buffer, bufferSize);
            if (ec == NABTO_EC_OK) {
                ctx.elms[i].active = true;
            }
            return;
        }
    }
}

np_error_code nc_client_connect_dispatch_close_connection(struct np_platform* pl,
                                                          struct nc_client_connection* conn)
{
    int i;
    for (i = 0; i<NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if (conn == &ctx.elms[i].conn) {
            ctx.elms[i].active = false;
        }
    }
}

