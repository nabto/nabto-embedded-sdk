#include "nc_client_connect.h"
#include <platform/np_error_code.h>
#include <platform/np_connection.h>
#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_CLIENT_CONNECT

struct nc_client_connection {
    struct np_platform* pl;
    bool active;
    np_connection conn;
    np_connection_received_callback recvCb;
    void* recvCbData;
    np_client_connect_created_callback createdCb;
    void* createdCbData;
    np_client_connect_close_callback closeCb;
    void* closeCbData;
    np_dtls_srv_connection* dtls;
};

struct nc_client_connect_context {
    struct nc_client_connection connections[NABTO_MAX_CLIENT_CONNECTIONS];
};

struct nc_client_connect_context ctx;

np_error_code nc_client_connect_init(struct np_platform* pl)
{
    pl->clientConn.async_create = &nc_client_connect_async_create;
    pl->clientConn.get_connection = &nc_client_connect_get_connection;
    pl->clientConn.recv = &nc_client_connect_recv;
    pl->clientConn.async_recv_from = &nc_client_connect_async_recv_from;
    memset(&ctx, 0, sizeof(struct nc_client_connect_context));
    return NABTO_EC_OK;
}

void nc_client_connect_dtls_created(const np_error_code ec, struct np_connection_id* id,
                                    np_dtls_srv_connection* dtls, void* data)
{
    struct nc_client_connection* cc = (struct nc_client_connection*)data;
    cc->dtls = dtls;
}

void nc_client_connect_conn_created(const np_error_code ec, uint8_t channelId, void* data)
{
    struct nc_client_connection* cc = (struct nc_client_connection*)data;
    np_error_code ecl;
    if (ec != NABTO_EC_OK) {
        cc->active = false;
        cc->createdCb(ec, NULL, cc->createdCbData);
        return;
    }
    ecl = cc->pl->dtlsS.create(cc->pl, &cc->conn, cc->dtls);
    cc->createdCb(ecl, cc->dtls, cc->createdCbData);
}

void nc_client_connect_connection_closed(const np_error_code ec, void* data)
{
    struct nc_client_connection* cc = (struct nc_client_connection*)data;
    cc->active = false;
    np_client_connect_close_callback cb = cc->closeCb;
    void* cbData = cc->closeCbData;
    memset(cc, 0, sizeof(struct nc_client_connection));
    cb(ec, cbData);
}

void nc_client_connect_dtls_closed(const np_error_code ec, void* data)
{
    struct nc_client_connection* cc = (struct nc_client_connection*)data;
    cc->pl->conn.async_destroy(cc->pl, &cc->conn, &nc_client_connect_connection_closed, data);
}


/* API functions */

np_error_code nc_client_connect_async_create(struct np_platform* pl, struct np_connection_id* id,
                                             struct np_udp_socket* sock, struct np_udp_endpoint* ep,
                                             np_client_connect_created_callback cb, void* data)
{
    int i = 0;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if(!ctx.connections[i].active) {
            struct np_connection_channel chan;
            chan.type = NABTO_CHANNEL_APP;
            chan.sock = sock;
            memcpy(&chan.ep, ep, sizeof(struct np_udp_endpoint));
            chan.channelId = id->id[15];
            ctx.connections[i].createdCb = cb;
            ctx.connections[i].createdCbData = data;
            ctx.connections[i].pl = pl;
            ctx.connections[i].active = true;
            pl->conn.async_create(pl, &ctx.connections[i].conn, &chan, id, &nc_client_connect_conn_created, &ctx.connections[i]);
            return NABTO_EC_OK;
        }
    }
    return NABTO_EC_INVALID_CONNECTION_ID;
}

np_connection* nc_client_connect_get_connection(struct np_platform* pl, struct np_connection_id* id)
{
    int i;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if (ctx.connections[i].active && memcmp(id, pl->conn.get_id(pl, &ctx.connections[i].conn), 16) == 0) {
            return &ctx.connections[i].conn;
        }
    }
    return NULL;
}

np_error_code nc_client_connect_recv(struct np_platform* pl, const np_error_code ec, struct np_udp_socket* sock, struct np_udp_endpoint ep,
                                     np_communication_buffer* buffer, uint16_t bufferSize)
{
    int i;
    uint8_t* id;
    if (ec != NABTO_EC_OK) {
        // TODO: THIS IS NOT MEANINGFULL
        return ec;
    }
    id = pl->buf.start(buffer);
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if (ctx.connections[i].active && memcmp(id, pl->conn.get_id(pl, &ctx.connections[i].conn), 16) == 0) {
            NABTO_LOG_INFO(LOG, "Found existing connection for new packet");
            // TODO: handle the packet
            return ec;
        }
    }
    NABTO_LOG_INFO(LOG, "Found packet for new connection");
    // TODO: pl->clientConn.async_create()
    return ec;
}

np_error_code nc_client_connect_async_recv_from(np_connection* conn,
                                                np_udp_packet_received_callback cb, void* data)
{
    return NABTO_EC_OK;
}

np_error_code nc_client_connect_async_close(struct np_platform* pl, struct np_connection_id* id, np_client_connect_close_callback cb, void* data)
{
    int i = 0;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if(memcmp(id, pl->conn.get_id(pl, &ctx.connections[i].conn), 16) == 0) {
            ctx.connections[i].closeCb = cb;
            ctx.connections[i].closeCbData = data;
            pl->dtlsS.async_close(pl, ctx.connections[i].dtls, &nc_client_connect_dtls_closed, &ctx.connections[i]);
            return NABTO_EC_OK;
        }
    }
    return NABTO_EC_INVALID_CONNECTION_ID;
}
