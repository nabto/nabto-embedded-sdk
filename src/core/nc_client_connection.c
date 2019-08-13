#include "nc_client_connection.h"
#include "nc_client_connection_dispatch.h"
#include "nc_device.h"

#include <core/nc_udp_dispatch.h>

#include <platform/np_error_code.h>
#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_CLIENT_CONNECTION

void nc_client_connection_async_send_to_udp(bool channelId,
                                         np_communication_buffer* buffer, uint16_t bufferSize,
                                         np_dtls_srv_send_callback cb, void* data, void* listenerData);
void nc_client_connection_mtu_discovered(const np_error_code ec, uint16_t mtu, void* data);

void nc_client_connection_handle_event(enum np_dtls_srv_event event, void* data);
void nc_client_connection_handle_data(uint8_t channelId, uint64_t sequence,
                                      np_communication_buffer* buffer, uint16_t bufferSize, void* data);

np_error_code nc_client_connection_open(struct np_platform* pl, struct nc_client_connection* conn,
                                        struct nc_client_connection_dispatch_context* dispatch,
                                        struct nc_device_context* device,
                                        struct nc_udp_dispatch_context* sock, struct np_udp_endpoint ep,
                                        np_communication_buffer* buffer, uint16_t bufferSize)
{
    np_error_code ec;
    uint8_t* start = pl->buf.start(buffer);
    memset(conn, 0, sizeof(struct nc_client_connection));
    memcpy(conn->id.id, pl->buf.start(buffer), 16);
    conn->currentChannel.sock = sock;
    conn->currentChannel.ep = ep;
    conn->currentChannel.channelId = conn->id.id[15];
    conn->lastChannel = conn->currentChannel;
    conn->pl = pl;
    conn->streamManager = &device->streamManager;
    conn->dispatch = dispatch;
    conn->rendezvous = &device->rendezvous;
    conn->connectionRef = nc_device_next_connection_ref(device);
    conn->device = device;

    ec = pl->dtlsS.create(pl, &conn->dtls,
                          &nc_client_connection_async_send_to_udp,
                          &nc_client_connection_handle_data,
                          &nc_client_connection_handle_event, conn);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to create DTLS server");
        return NABTO_EC_FAILED;
    }

    // Remove connection ID before passing packet to DTLS
    memmove(start, start+16, bufferSize-16);
    bufferSize = bufferSize-16;
    ec = pl->dtlsS.handle_packet(pl, conn->dtls, conn->currentChannel.channelId, buffer, bufferSize);
    return ec;
}

np_error_code nc_client_connection_handle_packet(struct np_platform* pl, struct nc_client_connection* conn,
                                                 struct nc_udp_dispatch_context* sock, struct np_udp_endpoint ep,
                                                 np_communication_buffer* buffer, uint16_t bufferSize)
{
    np_error_code ec;
    uint8_t* start = pl->buf.start(buffer);


    if (bufferSize >= 18 &&
        (start[0] == NABTO_PROTOCOL_PREFIX_RENDEZVOUS &&
         start[16] == AT_RENDEZVOUS &&
         start[17] == CT_RENDEZVOUS_CLIENT_REQUEST))
    {
        NABTO_LOG_INFO(LOG, "handle packet with rendezvous prefix");
        uint8_t connectionId[14];
        memcpy(connectionId, conn->id.id+1, 14);
        nc_rendezvous_handle_client_request(conn->rendezvous, ep, connectionId);
        return NABTO_EC_OK;
    }


    NABTO_LOG_TRACE(LOG, "handle packet for DTLS");
    conn->lastChannel.sock = sock;
    conn->lastChannel.ep = ep;
    conn->lastChannel.channelId = *(start+15);

    // Remove connection ID before passing packet to DTLS
    memmove(start, start+16, bufferSize-16);
    bufferSize = bufferSize-16;
    ec = pl->dtlsS.handle_packet(pl, conn->dtls, conn->lastChannel.channelId, buffer, bufferSize);
    return ec;
}

void nc_client_connection_close_connection(struct np_platform* pl, struct nc_client_connection* conn, np_error_code ec)
{
    nc_coap_server_remove_connection(&conn->device->coapServer, conn);
    nc_stream_manager_remove_connection(conn->streamManager, conn);
    nc_client_connection_dispatch_close_connection(conn->dispatch, conn);
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
        conn->pl->dtlsS.async_discover_mtu(conn->pl, conn->dtls, &nc_client_connection_mtu_discovered, conn);

        if (conn->pl->dtlsS.get_alpn_protocol(conn->dtls) == NULL) {
            NABTO_LOG_ERROR(LOG, "DTLS server Application Layer Protocol Negotiation failed");
            conn->pl->dtlsS.async_close(conn->pl, conn->dtls, &nc_client_connection_dtls_closed_cb, conn);
            return;
        }

        uint8_t fp[16];
        np_error_code ec2;
        ec2 = conn->pl->dtlsS.get_fingerprint(conn->pl, conn->dtls, fp);
        if (ec2 != NABTO_EC_OK) {
            NABTO_LOG_ERROR(LOG, "Failed to get fingerprint from DTLS connection");
            conn->pl->dtlsS.async_close(conn->pl, conn->dtls, &nc_client_connection_dtls_closed_cb, conn);
            return;
        }

        struct nc_iam_user* user = nc_iam_find_user_by_fingerprint(&conn->device->iam, fp);
        if (user == NULL && nc_iam_get_default_role(&conn->device->iam) == NULL) {
            NABTO_LOG_ERROR(LOG, "Client connect, cannot find a user and the system does not have a default role, closing the connection");
            conn->pl->dtlsS.async_close(conn->pl, conn->dtls, &nc_client_connection_dtls_closed_cb, conn);
            return;
        }
        conn->user = user;
    }
}

// handle data from the dtls module
void nc_client_connection_handle_data(uint8_t channelId, uint64_t sequence,
                                   np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    struct nc_client_connection* conn = (struct nc_client_connection*)data;
    uint8_t applicationType;

    if (conn->currentChannel.channelId != conn->lastChannel.channelId) {
        conn->currentChannel = conn->lastChannel;
    }

    applicationType = *(conn->pl->buf.start(buffer));
    if (applicationType == AT_STREAM) {
        NABTO_LOG_TRACE(LOG, "Received stream packet");
        nc_stream_manager_handle_packet(conn->streamManager, conn, buffer, bufferSize);
    } else if (applicationType >= AT_COAP_START && applicationType <= AT_COAP_END) {
        NABTO_LOG_TRACE(LOG, "Received COAP packet");
        nc_coap_server_handle_packet(&conn->device->coapServer, conn, buffer, bufferSize);
    } else {
        NABTO_LOG_ERROR(LOG, "unknown application data type: %u", applicationType);
    }
}

void nc_client_connection_dtls_closed_cb(const np_error_code ec, void* data)
{
    struct nc_client_connection* cc =  (struct nc_client_connection*)data;
    nc_client_connection_close_connection(cc->pl, cc, NABTO_EC_CONNECTION_CLOSING);
}

struct np_dtls_srv_connection* nc_client_connection_get_dtls_connection(struct nc_client_connection* conn)
{
    return conn->dtls;
}

void nc_client_connection_send_failed(void* data) {
    struct nc_client_connection* conn = (struct nc_client_connection*)data;
    if (conn->sentCb == NULL) {
        return;
    }
    np_dtls_srv_send_callback cb = conn->sentCb;
    conn->sentCb = NULL;
    cb(conn->ec, conn->sentData);
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


void nc_client_connection_async_send_to_udp(bool activeChannel,
                                         np_communication_buffer* buffer, uint16_t bufferSize,
                                         np_dtls_srv_send_callback cb, void* data, void* listenerData)
{
    struct nc_client_connection* conn = (struct nc_client_connection*)listenerData;
    conn->sentCb = cb;
    conn->sentData = data;
    if (bufferSize > conn->pl->buf.size(buffer)-16) {
        conn->ec = NABTO_EC_INSUFFICIENT_BUFFER_ALLOCATION;
        np_event_queue_post(conn->pl, &conn->ev, &nc_client_connection_send_failed, conn);
        return;
    }
    uint8_t* start = conn->pl->buf.start(buffer);
    memmove(start+16, start, bufferSize);
    memcpy(start, conn->id.id, 15);
    bufferSize = bufferSize + 16;
    NABTO_LOG_TRACE(LOG, "Connection sending %u bytes to UDP module", bufferSize);

    if (activeChannel) {
        *(start+15) = conn->currentChannel.channelId;
        nc_udp_dispatch_async_send_to(conn->currentChannel.sock, &conn->sendCtx, &conn->currentChannel.ep,
                                      buffer, bufferSize,
                                      &nc_client_connection_send_to_udp_cb, conn);
    } else {
        *(start+15) = conn->lastChannel.channelId;
        nc_udp_dispatch_async_send_to(conn->lastChannel.sock, &conn->sendCtx, &conn->lastChannel.ep,
                                      buffer, bufferSize,
                                      &nc_client_connection_send_to_udp_cb, conn);
    }
}

void nc_client_connection_mtu_discovered(const np_error_code ec, uint16_t mtu, void* data)
{
    // TODO: use the discovered MTU!
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
