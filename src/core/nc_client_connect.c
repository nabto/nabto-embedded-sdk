#include "nc_client_connect.h"
#include <platform/np_error_code.h>
#include <platform/np_connection.h>
#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_CLIENT_CONNECT

struct nc_client_connection {
    bool active;
    bool verified;
    
    // creation state
    np_communication_buffer* buf;
    uint16_t bufSize;
    np_connection conn;
    bool createdWithData;
    struct np_udp_endpoint recvEp;
    
    np_udp_packet_received_callback recvCb;
    void* recvCbData;
    np_client_connect_created_callback createdCb;
    void* createdCbData;
    np_client_connect_close_callback closeCb;
    void* closeCbData;
    np_dtls_srv_connection* dtls;
};

struct nc_client_connect_context {
    struct np_platform* pl;
    struct nc_client_connection connections[NABTO_MAX_CLIENT_CONNECTIONS];

    // TODO: FINGERPRINT FOR CLIENT VERIFICATION
    // Should not be done like this
    uint8_t* fp;

};

struct nc_client_connect_context ctx;

void nc_client_connect_dtlsS_closed_cb(const np_error_code ec, void* data) {
    struct nc_client_connection* cc =  (struct nc_client_connection*)data;
    cc->active = false;
}

void nc_client_connect_handle_app_packet(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                                         np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    struct nc_client_connection* cc =  (struct nc_client_connection*)data;
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_WARN(LOG, "DTLS server returned error code: %u", ec);
        cc->active = false;
        return;
    }
    if(!cc->verified) {
        if (ctx.pl->dtlsS.get_alpn_protocol(cc->dtls) == NULL) {
            NABTO_LOG_ERROR(LOG, "DTLS server Application Layer Protocol Negotiation failed");
            ctx.pl->dtlsS.async_close(ctx.pl, cc->dtls, &nc_client_connect_dtlsS_closed_cb, cc);
            return;
        }
        uint8_t fp[16];
        ctx.pl->dtlsS.get_fingerprint(ctx.pl, cc->dtls, fp);
        NABTO_LOG_TRACE(LOG, "Retreived FP: ");
        NABTO_LOG_BUF(LOG, fp, 16);
        if (memcmp(fp, ctx.fp, 16) == 0) {
            NABTO_LOG_ERROR(LOG, "Client connect fingerprint verification failed");
            ctx.pl->dtlsS.async_close(ctx.pl, cc->dtls, &nc_client_connect_dtlsS_closed_cb, cc);
            return;
        }
        cc->verified = true;
    }
    NABTO_LOG_TRACE(LOG, "Received packet from DTLS server:");
    NABTO_LOG_BUF(LOG, ctx.pl->buf.start(buffer), bufferSize);
    // TODO: handle the packet
}

// TODO: Do not take client fingerprint here!!
np_error_code nc_client_connect_init(struct np_platform* pl, uint8_t* fp)
{
    pl->clientConn.async_create = &nc_client_connect_async_create;
    pl->clientConn.get_connection = &nc_client_connect_get_connection;
    pl->clientConn.recv = &nc_client_connect_recv;
    pl->clientConn.async_recv_from = &nc_client_connect_async_recv_from;
    memset(&ctx, 0, sizeof(struct nc_client_connect_context));
    ctx.pl = pl;
    ctx.fp = fp;
    return NABTO_EC_OK;
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
    ecl = ctx.pl->dtlsS.create(ctx.pl, &cc->conn, &cc->dtls);
    NABTO_LOG_TRACE(LOG, "DTLS server created, createdCb: %u recvCb: %u", cc->createdCb, cc->recvCb);
    if (cc->createdCb != NULL) {
        cc->createdCb(ecl, cc->dtls, cc->createdCbData);
    }
    if( ecl == NABTO_EC_OK && cc->recvCb != NULL) {
        cc->recvCb(NABTO_EC_OK, cc->recvEp, cc->buf, cc->bufSize, cc->recvCbData);
    }
    ctx.pl->buf.free(cc->buf);
    ctx.pl->dtlsS.async_recv_from(ctx.pl, cc->dtls, AT_STREAM, &nc_client_connect_handle_app_packet, cc);
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
    ctx.pl->conn.async_destroy(ctx.pl, &cc->conn, &nc_client_connect_connection_closed, data);
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
            ctx.connections[i].createdWithData = false;
            ctx.connections[i].createdCb = cb;
            ctx.connections[i].createdCbData = data;
            ctx.connections[i].active = true;
            pl->conn.async_create(pl, &ctx.connections[i].conn, &chan, id, &nc_client_connect_conn_created, &ctx.connections[i]);
            return NABTO_EC_OK;
        }
    }
    return NABTO_EC_OUT_OF_CONNECTIONS;
}

np_connection* nc_client_connect_get_connection(struct np_platform* pl, struct np_connection_id* id)
{
    int i;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if (ctx.connections[i].active && memcmp(id->id, pl->conn.get_id(pl, &ctx.connections[i].conn)->id, 16) == 0) {
            return &ctx.connections[i].conn;
        }
    }
    return NULL;
}

np_error_code nc_client_connect_recv(struct np_platform* pl, const np_error_code ec,
                                     struct np_udp_socket* sock, struct np_udp_endpoint ep,
                                     np_communication_buffer* buffer, uint16_t bufferSize)
{
    int i;
    uint8_t* id;
    if (ec != NABTO_EC_OK) {
        // Do not handle socket errors, sockets are not connection specific
        return NABTO_EC_OK;
    }
    id = pl->buf.start(buffer);
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if (ctx.connections[i].active && memcmp(id, pl->conn.get_id(pl, &ctx.connections[i].conn)->id, 16) == 0) {
            NABTO_LOG_INFO(LOG, "Found existing connection for new packet");
            if(ctx.connections[i].recvCb != NULL) {
                ctx.connections[i].recvCb(ec, ep, buffer, bufferSize, ctx.connections[i].recvCbData);
                return NABTO_EC_OK;
            } else {
                return NABTO_EC_FAILED;
            }
        }
    }
    NABTO_LOG_INFO(LOG, "Found packet for new connection");
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if(!ctx.connections[i].active) {
            struct np_connection_channel chan;
            struct np_connection_id id;
            chan.type = NABTO_CHANNEL_APP;
            chan.sock = sock;
            chan.ep = ep;
            chan.channelId = pl->buf.start(buffer)[15];
            memcpy(id.id, pl->buf.start(buffer), 16);
            ctx.connections[i].createdWithData = true;
            ctx.connections[i].buf = pl->buf.allocate();
            memcpy(pl->buf.start(ctx.connections[i].buf), pl->buf.start(buffer), bufferSize);
            ctx.connections[i].bufSize = bufferSize;
            memcpy(&ctx.connections[i].recvEp, &ep, sizeof(ep));
            ctx.connections[i].createdCb = NULL;
            ctx.connections[i].active = true;
            ctx.connections[i].verified = false;
            pl->conn.async_create(pl, &ctx.connections[i].conn, &chan, &id, &nc_client_connect_conn_created, &ctx.connections[i]);
            return NABTO_EC_OK;
        }
    }
    return NABTO_EC_OUT_OF_CONNECTIONS;
}

np_error_code nc_client_connect_async_recv_from(np_connection* conn,
                                                np_udp_packet_received_callback cb, void* data)
{
    int i = 0;
    NABTO_LOG_TRACE(LOG, "recv_from");
    NABTO_LOG_TRACE(LOG, "incoming connection ID:");
    NABTO_LOG_BUF(LOG, ctx.pl->conn.get_id(ctx.pl, conn)->id, 16);
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if(ctx.connections[i].active) {
            NABTO_LOG_TRACE(LOG, "checking connection ID:");
            NABTO_LOG_BUF(LOG, ctx.pl->conn.get_id(ctx.pl, &ctx.connections[i].conn)->id, 16);
            if(memcmp(ctx.pl->conn.get_id(ctx.pl, conn)->id, ctx.pl->conn.get_id(ctx.pl, &ctx.connections[i].conn)->id, 16) == 0) {
                ctx.connections[i].recvCb = cb;
                ctx.connections[i].recvCbData = data;
                return NABTO_EC_OK;
            }
        }
    }
    NABTO_LOG_INFO(LOG, "recv_from called with unknown connection ID");
    return NABTO_EC_FAILED;
}

np_error_code nc_client_connect_cancel_recv_from(np_connection* conn)
{
    int i = 0;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if(ctx.connections[i].active) {
            NABTO_LOG_TRACE(LOG, "checking connection ID:");
            NABTO_LOG_BUF(LOG, ctx.pl->conn.get_id(ctx.pl, &ctx.connections[i].conn)->id, 16);
            if(memcmp(ctx.pl->conn.get_id(ctx.pl, conn)->id, ctx.pl->conn.get_id(ctx.pl, &ctx.connections[i].conn)->id, 16) == 0) {
                ctx.connections[i].recvCb = NULL;
                ctx.connections[i].recvCbData = NULL;
                return NABTO_EC_OK;
            }
        }
    }
    NABTO_LOG_INFO(LOG, "recv_from called with unknown connection ID");
    return NABTO_EC_FAILED;
    
}

np_error_code nc_client_connect_async_close(struct np_platform* pl, struct np_connection_id* id, np_client_connect_close_callback cb, void* data)
{
    int i = 0;
    for (i = 0; i < NABTO_MAX_CLIENT_CONNECTIONS; i++) {
        if(memcmp(id->id, pl->conn.get_id(pl, &ctx.connections[i].conn)->id, 16) == 0) {
            ctx.connections[i].closeCb = cb;
            ctx.connections[i].closeCbData = data;
            pl->dtlsS.async_close(pl, ctx.connections[i].dtls, &nc_client_connect_dtls_closed, &ctx.connections[i]);
            return NABTO_EC_OK;
        }
    }
    return NABTO_EC_INVALID_CONNECTION_ID;
}
