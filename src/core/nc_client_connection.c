#include "nc_client_connection.h"
#include "nc_client_connection_dispatch.h"
#include "nc_device.h"

#include <core/nc_udp_dispatch.h>

#include <platform/np_error_code.h>
#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_CLIENT_CONNECTION

np_error_code nc_client_connection_async_send_to_udp(uint8_t channelId,
                                                     uint8_t* buffer, uint16_t bufferSize,
                                                     np_dtls_srv_send_callback cb, void* data, void* listenerData);
void nc_client_connection_mtu_discovered(const np_error_code ec, uint16_t mtu, void* data);

void nc_client_connection_handle_event(enum np_dtls_srv_event event, void* data);
void nc_client_connection_handle_data(uint8_t channelId, uint64_t sequence,
                                      uint8_t* buffer, uint16_t bufferSize, void* data);

void nc_client_connection_handle_keep_alive(struct nc_client_connection* conn, uint8_t channelId, uint8_t* buffer, uint16_t bufferSize);
void nc_client_connection_keep_alive_start(struct nc_client_connection* conn);
void nc_client_connection_keep_alive_wait(struct nc_client_connection* conn);
void nc_client_connection_keep_alive_event(void* data);
void nc_client_connection_keep_alive_send_req(struct nc_client_connection* ctx);
void nc_client_connection_keep_alive_send_response(struct nc_client_connection* connection, uint8_t channelId, uint8_t* buffer, size_t length);
void nc_client_connection_keep_alive_packet_sent(const np_error_code ec, void* data);

static void nc_client_connection_send_to_udp_cb(const np_error_code ec, void* data);

np_error_code nc_client_connection_open(struct np_platform* pl, struct nc_client_connection* conn,
                                        struct nc_client_connection_dispatch_context* dispatch,
                                        struct nc_device_context* device,
                                        struct nc_udp_dispatch_context* sock, struct np_udp_endpoint* ep,
                                        uint8_t* buffer, uint16_t bufferSize)
{
    np_error_code ec;
    uint8_t* start = buffer;
    memset(conn, 0, sizeof(struct nc_client_connection));
    memcpy(conn->id.id, buffer, 16);
    conn->currentChannel.sock = sock;
    conn->currentChannel.ep = *ep;
    conn->currentChannel.channelId = conn->id.id[15];
    conn->alternativeChannel = conn->currentChannel;
    conn->pl = pl;
    conn->streamManager = &device->streamManager;
    conn->dispatch = dispatch;
    conn->rendezvous = &device->rendezvous;
    ec = nc_device_next_connection_ref(device, &conn->connectionRef);
    if (ec != NABTO_EC_OK) {
        return NABTO_EC_UNKNOWN;
    }
    conn->device = device;

    ec = nc_keep_alive_init(&conn->keepAlive, conn->pl, &nc_client_connection_keep_alive_event, conn);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(&pl->eq, &conn->sendCompletionEvent, &nc_client_connection_send_to_udp_cb, conn);
    if (ec != NABTO_EC_OK) {
        return ec;
    }


    ec = pl->dtlsS.create_connection(device->dtlsServer, &conn->dtls,
                                     &nc_client_connection_async_send_to_udp,
                                     &nc_client_connection_handle_data,
                                     &nc_client_connection_handle_event, conn);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to create DTLS server connection");
        return ec;
    }

    // Remove connection ID before passing packet to DTLS
    memmove(start, start+16, bufferSize-16);
    bufferSize = bufferSize-16;
    ec = pl->dtlsS.handle_packet(pl, conn->dtls, conn->currentChannel.channelId, buffer, bufferSize);
    NABTO_LOG_INFO(LOG, "Client <-> Device connection: %" PRIu64 " created.", conn->connectionRef);
    return ec;
}

np_error_code nc_client_connection_handle_packet(struct np_platform* pl, struct nc_client_connection* conn,
                                                 struct nc_udp_dispatch_context* sock, struct np_udp_endpoint* ep,
                                                 uint8_t* buffer, uint16_t bufferSize)
{
    np_error_code ec;
    uint8_t* start = buffer;


    if (bufferSize >= 17 &&
        (start[0] == NABTO_PROTOCOL_PREFIX_RENDEZVOUS &&
         start[16] == CT_RENDEZVOUS_CLIENT_REQUEST))
    {
        uint8_t connectionId[14];
        memcpy(connectionId, conn->id.id+1, 14);
        nc_rendezvous_handle_client_request(conn->rendezvous, ep, connectionId);
        return NABTO_EC_OK;
    }


    uint8_t channelId = *(start+15);

    if (channelId != conn->currentChannel.channelId) {
        conn->alternativeChannel.channelId = channelId;
        conn->alternativeChannel.ep = *ep;
        conn->alternativeChannel.sock = sock;
    } else {
        // not changed but update if we for whatever reason has a
        // changed view of the clients ip and socket on this channel
        // id.  If this was a keep alive on another channel the
        // channel id would not match and hence a keep alive would not
        // alter the current ep and socket.
        conn->currentChannel.ep = *ep;
        conn->currentChannel.sock = sock;
    }

    // Remove connection ID before passing packet to DTLS
    memmove(start, start+16, bufferSize-16);
    bufferSize = bufferSize-16;
    ec = pl->dtlsS.handle_packet(pl, conn->dtls, channelId, buffer, bufferSize);
    return ec;
}

void nc_client_connection_close_connection(struct nc_client_connection* conn)
{
    conn->pl->dtlsS.async_close(conn->pl, conn->dtls, &nc_client_connection_dtls_closed_cb, conn);
}

void nc_client_connection_destroy_connection(struct nc_client_connection* conn)
{
    struct np_platform* pl = conn->pl;
    NABTO_LOG_INFO(LOG, "Client <-> Device connection: %" PRIu64 " closed.", conn->connectionRef);
    nc_client_connection_event_listener_notify(conn, NC_CONNECTION_EVENT_CLOSED);
    nc_keep_alive_deinit(&conn->keepAlive);
    nc_coap_server_remove_connection(&conn->device->coapServer, conn);
    nc_stream_manager_remove_connection(conn->streamManager, conn);
    nc_client_connection_dispatch_close_connection(conn->dispatch, conn);
    pl->dtlsS.destroy_connection(conn->dtls);
    np_completion_event_deinit(&conn->sendCompletionEvent);

    memset(conn, 0, sizeof(struct nc_client_connection));
}

void nc_client_connection_handle_event(enum np_dtls_srv_event event, void* data)
{
    struct nc_client_connection* conn = (struct nc_client_connection*)data;
    if (event == NP_DTLS_SRV_EVENT_CLOSED) {
        nc_client_connection_dtls_closed_cb(NABTO_EC_OK, data);
    } else if (event == NP_DTLS_SRV_EVENT_HANDSHAKE_COMPLETE) {
        // test fingerprint and alpn
        // if ok try to assign user to connection.
        // if fail, reject the connection.
        //conn->pl->dtlsS.async_discover_mtu(conn->pl, conn->dtls, &nc_client_connection_mtu_discovered, conn);

        if (conn->pl->dtlsS.get_alpn_protocol(conn->dtls) == NULL) {
            NABTO_LOG_ERROR(LOG, "DTLS server Application Layer Protocol Negotiation failed");
            conn->pl->dtlsS.async_close(conn->pl, conn->dtls, &nc_client_connection_dtls_closed_cb, conn);
            return;
        }

        nc_client_connection_keep_alive_start(conn);
        nc_client_connection_event_listener_notify(conn, NC_CONNECTION_EVENT_OPENED);
    }
}

// handle data from the dtls module
void nc_client_connection_handle_data(uint8_t channelId, uint64_t sequence,
                                      uint8_t* buffer, uint16_t bufferSize, void* data)
{
    struct nc_client_connection* conn = (struct nc_client_connection*)data;
    uint8_t applicationType;

    applicationType = *(buffer);

    // if the packet received is not a keep alive poacket and the
    // sequence number is larger than a previous seen sequence number
    // then we should switch to the new channel if that channel is
    // different from the current channel in use.

    if (applicationType != AT_KEEP_ALIVE) {
        if (sequence > conn->currentMaxSequence) {
            conn->currentMaxSequence = sequence;
            if (conn->currentChannel.channelId != channelId && conn->alternativeChannel.channelId == channelId) {
                conn->currentChannel = conn->alternativeChannel;
                nc_client_connection_event_listener_notify(conn, NC_CONNECTION_EVENT_CHANNEL_CHANGED);
            }
        }
    }


    if (applicationType == AT_STREAM) {
        //NABTO_LOG_TRACE(LOG, "Received stream packet");
        nc_stream_manager_handle_packet(conn->streamManager, conn, buffer, bufferSize);
    } else if (applicationType >= AT_COAP_START && applicationType <= AT_COAP_END) {
        //NABTO_LOG_TRACE(LOG, "Received COAP packet");
        nc_coap_server_handle_packet(&conn->device->coapServer, conn, buffer, bufferSize);
    } else if (applicationType == AT_KEEP_ALIVE) {
        //NABTO_LOG_TRACE(LOG, "Received KeepAlive packet");
        nc_client_connection_handle_keep_alive(conn, channelId, buffer, bufferSize);
    } else {
        NABTO_LOG_ERROR(LOG, "unknown application data type: %u", applicationType);
    }
}

void nc_client_connection_handle_keep_alive(struct nc_client_connection* conn, uint8_t channelId, uint8_t* buffer, uint16_t bufferSize)
{
    uint8_t* start = buffer;
    if (bufferSize < 2) {
        return;
    }
    uint8_t contentType = start[1];
    if (contentType == CT_KEEP_ALIVE_REQUEST) {
        nc_client_connection_keep_alive_send_response(conn, channelId, start, bufferSize);
    } else if (contentType == CT_KEEP_ALIVE_RESPONSE) {
        // Do nothing, the fact that we did get a packet increases the vital counters.
    }
}

void nc_client_connection_keep_alive_start(struct nc_client_connection* ctx)
{
    nc_keep_alive_wait(&ctx->keepAlive);
}

void nc_client_connection_keep_alive_event(void* data)
{
    struct nc_client_connection* ctx = (struct nc_client_connection*)data;
    struct np_platform* pl = ctx->pl;

    uint32_t recvCount;
    uint32_t sentCount;

    pl->dtlsS.get_packet_count(ctx->dtls, &recvCount, &sentCount);
    enum nc_keep_alive_action action = nc_keep_alive_should_send(&ctx->keepAlive, recvCount, sentCount);
    switch(action) {
        case DO_NOTHING:
            nc_keep_alive_wait(&ctx->keepAlive);
            break;
        case SEND_KA:
            nc_client_connection_keep_alive_send_req(ctx);
            nc_keep_alive_wait(&ctx->keepAlive);
            break;
        case KA_TIMEOUT:
            NABTO_LOG_INFO(LOG, "Closed connection because of keep alive timeout.");
            nc_client_connection_close_connection(ctx);
            break;
    }
}

void nc_client_connection_keep_alive_send_req(struct nc_client_connection* ctx)
{
    struct np_platform* pl = ctx->pl;
    struct np_dtls_srv_send_context* sendCtx = &ctx->keepAliveSendCtx;

    nc_keep_alive_create_request(&ctx->keepAlive, &sendCtx->buffer, (size_t*)&sendCtx->bufferSize);
    sendCtx->cb = &nc_keep_alive_packet_sent;
    sendCtx->data = &ctx->keepAlive;
    sendCtx->channelId = ctx->currentChannel.channelId;
    pl->dtlsS.async_send_data(pl, ctx->dtls, sendCtx);
}

void nc_client_connection_keep_alive_send_response(struct nc_client_connection* ctx, uint8_t channelId, uint8_t* buffer, size_t length)
{
    struct np_platform* pl = ctx->pl;
    struct np_dtls_srv_send_context* sendCtx = &ctx->keepAliveSendCtx;
    if(nc_keep_alive_handle_request(&ctx->keepAlive, buffer, length, &sendCtx->buffer, (size_t*)&sendCtx->bufferSize)) {
        sendCtx->cb = &nc_keep_alive_packet_sent;
        sendCtx->data = &ctx->keepAlive;
        sendCtx->channelId = channelId;
        pl->dtlsS.async_send_data(pl, ctx->dtls, sendCtx);
    }
}

void nc_client_connection_dtls_closed_cb(const np_error_code ec, void* data)
{
    struct nc_client_connection* cc =  (struct nc_client_connection*)data;
    nc_client_connection_destroy_connection(cc);
}

struct np_dtls_srv_connection* nc_client_connection_get_dtls_connection(struct nc_client_connection* conn)
{
    return conn->dtls;
}

void nc_client_connection_send_to_udp_cb(const np_error_code ec, void* data)
{
    struct nc_client_connection* conn = (struct nc_client_connection*)data;
    if (conn->sentCb == NULL) {
        return;
    }
    np_dtls_srv_send_callback cb = conn->sentCb;
    conn->sentCb = NULL;
    cb(ec, conn->sentData);
}

np_error_code nc_client_connection_async_send_to_udp(uint8_t channel,
                                                     uint8_t* buffer, uint16_t bufferSize,
                                                     np_dtls_srv_send_callback cb, void* data, void* listenerData)
{
    struct nc_client_connection* conn = (struct nc_client_connection*)listenerData;

    if (conn->sentCb != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }
    conn->sentCb = cb;
    conn->sentData = data;

    uint8_t* start = buffer;
    memmove(start+16, start, bufferSize);
    memcpy(start, conn->id.id, 15);
    bufferSize = bufferSize + 16;

    if (channel == conn->currentChannel.channelId || channel == NP_DTLS_SRV_DEFAULT_CHANNEL_ID) {
        *(start+15) = conn->currentChannel.channelId;
        nc_udp_dispatch_async_send_to(conn->currentChannel.sock, &conn->currentChannel.ep,
                                      start, bufferSize,
                                      &conn->sendCompletionEvent);
    } else if (channel == conn->alternativeChannel.channelId) {
        *(start+15) = conn->alternativeChannel.channelId;
        nc_udp_dispatch_async_send_to(conn->alternativeChannel.sock, &conn->alternativeChannel.ep,
                                      start, bufferSize,
                                      &conn->sendCompletionEvent);
    }
    return NABTO_EC_OK;
}

void nc_client_connection_mtu_discovered(const np_error_code ec, uint16_t mtu, void* data)
{
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_INFO(LOG, "MTU discovery failed with %s. mtu is %u", np_error_code_to_string(ec), mtu);
    } else {
        NABTO_LOG_INFO(LOG, "MTU discovered to be %u", mtu);
    }
}

np_error_code nc_client_connection_get_client_fingerprint(struct nc_client_connection* conn, uint8_t* fp)
{
    return conn->pl->dtlsS.get_fingerprint(conn->pl, conn->dtls, fp);
}

bool nc_client_connection_is_local(struct nc_client_connection* conn)
{
    return (&conn->device->localUdp == conn->currentChannel.sock);
}

void nc_client_connection_event_listener_notify(struct nc_client_connection* conn, enum nc_connection_event event)
{
    nc_device_connection_events_listener_notify(conn->device, conn->connectionRef, event);

}
