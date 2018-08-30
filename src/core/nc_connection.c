#include "nc_connection.h"
#include <platform/np_event_queue.h>
#include <platform/np_error_code.h>
#include <platform/np_logging.h>
#include <string.h>

#define LOG NABTO_LOG_MODULE_CONNECTION

void nc_connection_init(struct np_platform* pl)
{
    pl->conn.async_create = &nc_connection_async_create;
    pl->conn.add_channel = &nc_connection_add_channel;
    pl->conn.rem_channel = &nc_connection_rem_channel;
    pl->conn.async_send_to = &nc_connection_async_send_to;
    pl->conn.async_recv_from = &nc_connection_async_recv_from;
    pl->conn.async_destroy = &nc_connection_async_destroy;
    pl->conn.cancel_async_recv = &nc_connection_cancel_async_recv;
    pl->conn.get_id = &nc_connection_get_id;
}

struct np_connection_id* nc_connection_get_id(struct np_platform* pl, np_connection* conn)
{
    return &conn->id;
}

np_error_code nc_connection_cancel_async_recv(struct np_platform* pl, np_connection* conn)
{
    conn->recvCb = NULL;
    return NABTO_EC_OK;
}

void createdFailed(void* data)
{
    np_connection* conn = (np_connection*)data;
    conn->createCb(conn->ec, 0, conn->createData);
}

void createdCb(void* data)
{
    np_connection* conn = (np_connection*)data;
    conn->createCb(NABTO_EC_OK, conn->id.id[15], conn->createData);
}

void sentFailed(void* data)
{
    np_connection* conn = (np_connection*)data;
    conn->sentCb(conn->ec, conn->sentData);
}

void sentCb(const np_error_code ec, void* data)
{
    np_connection* conn = (np_connection*)data;
    conn->sentCb(ec, conn->sentData);
}

void recvCb(const np_error_code ec, struct np_udp_endpoint ep, np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    np_connection* conn = (np_connection*)data;
    NABTO_LOG_INFO(LOG, "recieved callback from udp module");
    if(conn->recvCb) {
        uint8_t* start = conn->pl->buf.start(buffer);
        uint8_t channelId = 0;
        if (ec != NABTO_EC_OK) {
        } else if (*start == 0 || *start == 1) {
            // STUN
            for (int i = 0; i < NABTO_CONNECTION_MAX_CHANNELS; i++) {
                if (conn->channels[i].type == NABTO_CHANNEL_STUN) {
                    conn->channels[i].ep = ep;
                }
            }
        } else if (*start >= 20 && *start <= 64) {
            // DTLS
            for (int i = 0; i < NABTO_CONNECTION_MAX_CHANNELS; i++) {
                if (conn->channels[i].type == NABTO_CHANNEL_DTLS) {
                    conn->channels[i].ep = ep;
                }
            }
        } else if (*start > 192) {
            channelId = start[15];
            memmove(start, start+16, bufferSize);
            for (int i = 0; i < NABTO_CONNECTION_MAX_CHANNELS; i++) {
                if (conn->channels[i].channelId == channelId) {
                    conn->channels[i].ep = ep;
                }
            }
        }// if STUN or DTLS packet, channel IDs are not used
        np_connection_received_callback cb = conn->recvCb;
        conn->recvCb = NULL;
        cb(ec, conn, channelId, buffer, bufferSize, conn->recvData);
    } else {
        NABTO_LOG_INFO(LOG, "NO callback for data received from UDP");
    }
}

void destroyedCb(void* data) {
    np_connection* conn = (np_connection*)data;
    np_connection_destroyed_callback cb = conn->desCb;
    void* d = conn->desData;
    cb(NABTO_EC_OK, d);
}

void nc_connection_async_create(struct np_platform* pl, np_connection* conn, struct np_connection_channel* channel,
                                struct np_connection_id* id, np_connection_created_callback cb, void* data)
{
    memset(conn, 0, sizeof(np_connection));
    memcpy(&conn->channels[0], channel, sizeof(struct np_connection_channel));
    conn->createCb = cb;
    conn->createData = data;
    memcpy(&conn->id, id, sizeof(struct np_connection_id));

    np_event_queue_post(pl, &conn->ev, createdCb, conn);
}

np_error_code nc_connection_add_channel(struct np_platform* pl, np_connection* conn,
                                        struct np_connection_channel* channel)
{
    int found = 0;
    for (int i = 0; i<NABTO_CONNECTION_MAX_CHANNELS; i++) {
        if( conn->channels[i].sock == NULL ) {
            memcpy(&conn->channels[i], channel, sizeof(struct np_connection_channel));
            found = 1;
            break;
        }
    }
    if (found == 0) {
        return NABTO_EC_OUT_OF_CHANNELS;
    }
    return NABTO_EC_OK;

}

np_error_code nc_connection_rem_channel(struct np_platform* pl, np_connection* conn, uint8_t channelId)
{
    for (int i = 0; i < NABTO_CONNECTION_MAX_CHANNELS; i++) {
        if (conn->channels[i].channelId == channelId) {
            conn->channels[i].sock = NULL;
            conn->channels[i].channelId = 0;
            return NABTO_EC_OK;
        }
    }
    return NABTO_EC_INVALID_CHANNEL;
}

void nc_connection_async_send_to(struct np_platform* pl, np_connection* conn, uint8_t channelId,
                                 np_communication_buffer* buffer, uint16_t bufferSize,
                                 np_connection_sent_callback cb, void* data)
{
    conn->sentCb = cb;
    conn->sentData = data;
    bool found = false;
    for (int i = 0; i < NABTO_CONNECTION_MAX_CHANNELS; i++) {
        if (conn->channels[i].channelId == channelId) {
            if(conn->channels[i].type == NABTO_CHANNEL_APP) {
                if (bufferSize > pl->buf.size(buffer)-16) {
                    conn->ec = NABTO_EC_INSUFFICIENT_BUFFER_ALLOCATION;
                    np_event_queue_post(pl, &conn->ev, sentFailed, conn);
                    return;
                }
                uint8_t* start = pl->buf.start(buffer);
                memmove(start+16, start, bufferSize);
                memcpy(start, conn->id.id, 15);
                memcpy(start+15, &channelId, 1);
                bufferSize = bufferSize + 16;
            }
            NABTO_LOG_TRACE(LOG, "Connection sending %u bytes to UDP module", bufferSize);
            pl->udp.async_send_to(conn->channels[i].sock, &conn->channels[i].ep, buffer, bufferSize, sentCb, conn);
            found = true;
            break;
        }
        if (!found) {
            conn->ec = NABTO_EC_INVALID_CHANNEL;
            np_event_queue_post(pl, &conn->ev, sentFailed, conn);
        }
    }
}

void nc_connection_async_recv_from(struct np_platform* pl, np_connection* conn, np_connection_received_callback cb, void* data)
{
    NABTO_LOG_INFO(LOG, "registering recv callback");
    conn->recvCb = cb;
    conn->recvData = data;
    conn->pl = pl;
    for (int i = 0; i < NABTO_CONNECTION_MAX_CHANNELS; i++) {
        if (conn->channels[i].sock) {
            if(conn->channels[i].type == NABTO_CHANNEL_DTLS) {
                pl->udp.async_recv_from(conn->channels[i].sock, NABTO_CHANNEL_DTLS, recvCb, conn);
            } else if (conn->channels[i].type == NABTO_CHANNEL_STUN) {
                pl->udp.async_recv_from(conn->channels[i].sock, NABTO_CHANNEL_STUN, recvCb, conn);
            } else {
                pl->clientConn.async_recv_from(conn, recvCb, conn);
            }
        }
    }
}

void nc_connection_async_destroy(struct np_platform* pl, np_connection* conn, np_connection_destroyed_callback cb, void* data)
{
    conn->desCb = cb;
    conn->desData = data;
    np_event_queue_post(pl, &conn->ev, destroyedCb, conn);
}

