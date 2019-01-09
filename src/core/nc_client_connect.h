#ifndef NC_CLIENT_CONNECT_H
#define NC_CLIENT_CONNECT_H

#include <platform/np_platform.h>
#include <core/nc_rendezvous.h>
#include <core/nc_stream_manager.h>
#include <core/nc_coap.h>

#define NC_CLIENT_CONNECT_MAX_CHANNELS 16

struct nc_stream_manager_context;
struct nc_udp_dispatch_context;

typedef void (*nc_client_connect_send_callback)(const np_error_code ec, void* data);

struct nc_connection_channel {
    struct nc_udp_dispatch_context* sock;
    np_udp_endpoint ep;
    uint8_t channelId;
};

struct nc_connection_id {
    uint8_t id[16];
};

struct nc_client_connection {
    struct np_platform* pl;
    struct np_dtls_srv_connection* dtls;
    struct nc_client_connect_dispatch_context* dispatch;
    struct nc_stream_manager_context* streamManager;
    struct nc_stun_context* stun;
    struct nc_coap_context* coap;
    struct nc_rendezvous_context rendezvous;
    struct nc_connection_id id;
    uint8_t clientFingerprint[16];
    bool verified;
    struct nc_connection_channel currentChannel;
    struct nc_connection_channel lastChannel;

    struct np_event ev;    

    np_dtls_srv_send_callback sentCb;
    void* sentData;
    struct np_udp_send_context sendCtx;
    nc_client_connect_send_callback sentToEpCb;
    void* sentToEpCbData;
    struct np_udp_send_context sendToEpCtx;

    np_error_code ec;
};


np_error_code nc_client_connect_open(struct np_platform* pl, struct nc_client_connection* conn,
                                     struct nc_client_connect_dispatch_context* dispatch,
                                     struct nc_stream_manager_context* streamManager,
                                     struct nc_stun_context* stun,
                                     struct nc_coap_context* coap,
                                     struct nc_udp_dispatch_context* sock, struct np_udp_endpoint ep,
                                     np_communication_buffer* buffer, uint16_t bufferSize);

np_error_code nc_client_connect_handle_packet(struct np_platform* pl, struct nc_client_connection* conn,
                                              struct nc_udp_dispatch_context* sock, struct np_udp_endpoint ep,
                                              np_communication_buffer* buffer, uint16_t bufferSize);

void nc_client_connect_close_connection(struct np_platform* pl, struct nc_client_connection* conn,
                                        np_error_code ec);

void nc_client_connect_dtls_recv_callback(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                                          np_communication_buffer* buffer, uint16_t bufferSize, void* data);

void nc_client_connect_dtls_closed_cb(const np_error_code ec, void* data);

struct np_dtls_srv_connection* nc_client_connect_get_dtls_connection(struct nc_client_connection* conn);

np_error_code nc_client_connect_async_send_to_ep(struct nc_client_connection* conn,
                                                 struct np_udp_endpoint* ep,
                                                 np_communication_buffer* buffer, uint16_t bufferSize,
                                                 nc_client_connect_send_callback cb, void* data);
#endif //_NC_CLIENT_CONNECT_H_
