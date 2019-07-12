#include "nc_client_connect.h"
#include "nc_client_connect_dispatch.h"
#include "nc_device.h"

#include <core/nc_udp_dispatch.h>

#include <platform/np_error_code.h>
#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_CLIENT_CONNECT

void nc_client_connect_async_send_to_udp(bool channelId,
                                         np_communication_buffer* buffer, uint16_t bufferSize,
                                         np_dtls_srv_send_callback cb, void* data, void* listenerData);
void nc_client_connect_mtu_discovered(const np_error_code ec, uint16_t mtu, void* data);

np_error_code nc_client_connect_open(struct np_platform* pl, struct nc_client_connection* conn,
                                     struct nc_client_connect_dispatch_context* dispatch,
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
    conn->coap = &device->coap;
    conn->rendezvous = &device->rendezvous;
    conn->connectionRef = nc_device_next_connection_ref(device);
    conn->userRef = 0;

    ec = pl->dtlsS.create(pl, &conn->dtls, &nc_client_connect_async_send_to_udp, conn);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to create DTLS server");
        return NABTO_EC_FAILED;
    }

    pl->dtlsS.async_recv_from(pl, conn->dtls, &nc_client_connect_dtls_recv_callback, conn);
    // Remove connection ID before passing packet to DTLS
    memmove(start, start+16, bufferSize-16);
    bufferSize = bufferSize-16;
    ec = pl->dtlsS.handle_packet(pl, conn->dtls, conn->currentChannel.channelId, buffer, bufferSize);
    return ec;
}

np_error_code nc_client_connect_handle_packet(struct np_platform* pl, struct nc_client_connection* conn,
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

void nc_client_connect_close_connection(struct np_platform* pl, struct nc_client_connection* conn, np_error_code ec)
{
    nc_coap_server_remove_connection(conn->coap, conn);
    nc_stream_manager_remove_connection(conn->streamManager, conn);
    nc_client_connect_dispatch_close_connection(conn->dispatch, conn);
    memset(conn, 0, sizeof(struct nc_client_connection));
}

void nc_client_connect_dtls_recv_callback(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                                          np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    struct nc_client_connection* conn = (struct nc_client_connection*)data;
    uint8_t applicationType;

    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "DTLS server returned error: %u", ec);
        //conn->pl->dtlsS.async_close(conn->pl, conn->dtls, &nc_client_connect_dtls_closed_cb, conn);
        nc_client_connect_dtls_closed_cb(NABTO_EC_OK, data);
        return;
    }

    if (conn->currentChannel.channelId != conn->lastChannel.channelId) {
        conn->currentChannel = conn->lastChannel;
    }

    if(!conn->verified) {
        conn->pl->dtlsS.async_discover_mtu(conn->pl, conn->dtls, &nc_client_connect_mtu_discovered, conn);
        if (conn->pl->dtlsS.get_alpn_protocol(conn->dtls) == NULL) {
            NABTO_LOG_ERROR(LOG, "DTLS server Application Layer Protocol Negotiation failed");
            conn->pl->dtlsS.async_close(conn->pl, conn->dtls, &nc_client_connect_dtls_closed_cb, conn);
            return;
        }
        uint8_t fp[16];
        np_error_code ec2;
        ec2 = conn->pl->dtlsS.get_fingerprint(conn->pl, conn->dtls, fp);
        if (ec2 != NABTO_EC_OK) {
            NABTO_LOG_ERROR(LOG, "Failed to get fingerprint from DTLS connection");
            conn->pl->dtlsS.async_close(conn->pl, conn->dtls, &nc_client_connect_dtls_closed_cb, conn);
            return;
        }
        NABTO_LOG_TRACE(LOG, "Retreived FP: ");
        NABTO_LOG_BUF(LOG, fp, 16);
        memcpy(conn->clientFingerprint, fp, 16);
        if (!conn->pl->accCtrl.can_access(fp, NP_CONNECT_PERMISSION)) {
            NABTO_LOG_ERROR(LOG, "Client connect fingerprint verification failed");
            conn->pl->dtlsS.async_close(conn->pl, conn->dtls, &nc_client_connect_dtls_closed_cb, conn);
            return;
        }
        conn->verified = true;
    }

    applicationType = *(conn->pl->buf.start(buffer));
    if (applicationType == AT_STREAM) {
        NABTO_LOG_TRACE(LOG, "Received stream packet");
        nc_stream_manager_handle_packet(conn->streamManager, conn, buffer, bufferSize);
    } else if (applicationType >= AT_COAP_START && applicationType <= AT_COAP_END) {
        NABTO_LOG_TRACE(LOG, "Received COAP packet");
        nc_coap_server_handle_packet(conn->coap, conn, buffer, bufferSize);
    } else {
        NABTO_LOG_ERROR(LOG, "unknown application data type: %u", applicationType);
    }
    conn->pl->dtlsS.async_recv_from(conn->pl, conn->dtls, &nc_client_connect_dtls_recv_callback, conn);
}

void nc_client_connect_dtls_closed_cb(const np_error_code ec, void* data)
{
    struct nc_client_connection* cc =  (struct nc_client_connection*)data;
    nc_client_connect_close_connection(cc->pl, cc, NABTO_EC_CONNECTION_CLOSING);
}

struct np_dtls_srv_connection* nc_client_connect_get_dtls_connection(struct nc_client_connection* conn)
{
    return conn->dtls;
}

void nc_client_connect_send_failed(void* data) {
    struct nc_client_connection* conn = (struct nc_client_connection*)data;
    if (conn->sentCb == NULL) {
        return;
    }
    np_dtls_srv_send_callback cb = conn->sentCb;
    conn->sentCb = NULL;
    cb(conn->ec, conn->sentData);
}

void nc_client_connect_send_to_udp_cb(const np_error_code ec, void* data)
{
    struct nc_client_connection* conn = (struct nc_client_connection*)data;
    if (conn->sentCb == NULL) {
        return;
    }
    np_dtls_srv_send_callback cb = conn->sentCb;
    conn->sentCb = NULL;
    cb(ec, conn->sentData);
}


void nc_client_connect_async_send_to_udp(bool activeChannel,
                                         np_communication_buffer* buffer, uint16_t bufferSize,
                                         np_dtls_srv_send_callback cb, void* data, void* listenerData)
{
    struct nc_client_connection* conn = (struct nc_client_connection*)listenerData;
    conn->sentCb = cb;
    conn->sentData = data;
    if (bufferSize > conn->pl->buf.size(buffer)-16) {
        conn->ec = NABTO_EC_INSUFFICIENT_BUFFER_ALLOCATION;
        np_event_queue_post(conn->pl, &conn->ev, &nc_client_connect_send_failed, conn);
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
                                      &nc_client_connect_send_to_udp_cb, conn);
    } else {
        *(start+15) = conn->lastChannel.channelId;
        nc_udp_dispatch_async_send_to(conn->lastChannel.sock, &conn->sendCtx, &conn->lastChannel.ep,
                                      buffer, bufferSize,
                                      &nc_client_connect_send_to_udp_cb, conn);
    }
}

void nc_client_connect_mtu_discovered(const np_error_code ec, uint16_t mtu, void* data)
{
    // TODO: use the discovered MTU!
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_INFO(LOG, "MTU discovery failed with %s. mtu is %u", np_error_code_to_string(ec), mtu);
    } else {
        NABTO_LOG_INFO(LOG, "MTU discovered to be %u", mtu);
    }
}
