#ifndef NC_CLIENT_CONNECTION_H
#define NC_CLIENT_CONNECTION_H

#include <platform/np_platform.h>
#include <core/nc_rendezvous.h>
#include <core/nc_stream_manager.h>
#include <core/nc_coap_server.h>
#include <core/nc_keep_alive.h>
//#include <core/nc_device.h>

#define NC_CLIENT_CONNECTION_MAX_CHANNELS 16

struct nc_stream_manager_context;
struct nc_udp_dispatch_context;
struct nc_device_context;

typedef void (*nc_client_connection_send_callback)(const np_error_code ec, void* data);

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
    struct nc_client_connection_dispatch_context* dispatch;
    struct nc_stream_manager_context* streamManager;
    struct nc_stun_context* stun;
    struct nc_rendezvous_context* rendezvous;
    struct nc_connection_id id;
    struct nc_connection_channel currentChannel;
    struct nc_connection_channel alternativeChannel;
    uint64_t currentMaxSequence;
    struct nc_device_context* device;
    struct nc_iam_user* user;

    struct np_event ev;

    np_dtls_srv_send_callback sentCb;
    void* sentData;
    struct np_udp_send_context sendCtx;
    np_error_code ec;
    uint64_t connectionRef;


    struct nc_keep_alive_context keepAlive;
    struct np_dtls_srv_send_context keepAliveSendCtx;
};

np_error_code nc_client_connection_open(struct np_platform* pl, struct nc_client_connection* conn,
                                     struct nc_client_connection_dispatch_context* dispatch,
                                     struct nc_device_context* device,
                                     struct nc_udp_dispatch_context* sock, struct np_udp_endpoint ep,
                                     uint8_t* buffer, uint16_t bufferSize);

np_error_code nc_client_connection_handle_packet(struct np_platform* pl, struct nc_client_connection* conn,
                                              struct nc_udp_dispatch_context* sock, struct np_udp_endpoint ep,
                                              uint8_t* buffer, uint16_t bufferSize);

void nc_client_connection_close_connection(struct nc_client_connection* conn);

void nc_client_connection_dtls_recv_callback(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                                          uint8_t* buffer, uint16_t bufferSize, void* data);

void nc_client_connection_dtls_closed_cb(const np_error_code ec, void* data);

struct np_dtls_srv_connection* nc_client_connection_get_dtls_connection(struct nc_client_connection* conn);

np_error_code nc_client_connection_get_client_fingerprint(struct nc_client_connection* conn, uint8_t* fp);

#endif //_NC_CLIENT_CONNECTION_H_
