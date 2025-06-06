#ifndef NC_CLIENT_CONNECTION_H
#define NC_CLIENT_CONNECTION_H

#include <core/nc_coap_server.h>
#include <core/nc_connection_event.h>
#include <core/nc_keep_alive.h>
#include <core/nc_spake2.h>
#include <core/nc_stream_manager.h>
#include <nabto/nabto_device_config.h>
#include <platform/np_completion_event.h>
#include <platform/np_platform.h>

#include <nn/llist.h>

#define NC_CLIENT_CONNECTION_MAX_CHANNELS 16

struct nc_stream_manager_context;
struct nc_udp_dispatch_context;
struct nc_device_context;

typedef void (*nc_client_connection_send_callback)(const np_error_code ec, void* data);

struct nc_connection_channel {
    struct nc_udp_dispatch_context* sock;
    struct np_udp_endpoint ep;
    uint8_t channelId;
};

struct nc_connection_id {
    uint8_t id[16];
};

struct nc_client_connection {
    struct nn_llist_node connectionsNode;
    struct np_platform* pl;
#if defined(NABTO_DEVICE_DTLS_CLIENT_ONLY)
    struct np_dtls_cli_connection* dtls;
#else
    struct np_dtls_srv_connection* dtls;
#endif
    struct nc_client_connection_dispatch_context* dispatch;
    struct nc_stream_manager_context* streamManager;
    struct nc_stun_context* stun;
    struct nc_connection_id id;
    struct nc_connection_channel currentChannel;
    struct nc_connection_channel alternativeChannel;
    uint64_t currentMaxSequence;
    struct nc_device_context* device;
    struct nc_connection* parent;

    struct np_completion_event* sentCb;
    struct np_completion_event sendCompletionEvent;
    struct np_completion_event closeCompletionEvent;

    struct nc_keep_alive_context keepAlive;
    struct np_dtls_send_context keepAliveSendCtx;

};

/**
 * Open new client connection. Called by nc_client_connection_dispatch
 * when client hello arrives on unknown connection id.
 *
 * Initializes client connection, creates a DTLS Server connection,
 * and forwards the hello packet to DTLS.
 */
np_error_code nc_client_connection_init(struct np_platform* pl, struct nc_client_connection* conn,
                                     struct nc_client_connection_dispatch_context* dispatch,
                                     struct nc_device_context* device,
                                     struct nc_udp_dispatch_context* sock, struct np_udp_endpoint* ep,
                                     uint8_t* buffer, uint16_t bufferSize);

np_error_code nc_client_connection_start(struct nc_client_connection* conn, uint8_t* buffer, size_t bufferSize);

/**
 * Handles packets coming from nc_client_connection_dispatch when a
 * connection ID is known.
 *
 * Handles channel updates and dispatches the packet to rendezvous or
 * DTLS.
 */
np_error_code nc_client_connection_handle_packet(struct np_platform* pl, struct nc_client_connection* conn,
                                              struct nc_udp_dispatch_context* sock, struct np_udp_endpoint* ep,
                                              uint8_t* buffer, uint16_t bufferSize);

/**
 * Closes connection. Either called from self or by
 * nc_client_connection_dispatch on system closeure.
 *
 * Simply closes the DTLS connection.
 */
void nc_client_connection_close_connection(struct nc_client_connection* conn);

/**
 * Destroy connection and clean up making the structure available for
 * new connections.
 *
 * called by self on DTLS connection closed or from
 * nc_client_connection_dispatch on system wide deinit.
 */
void nc_client_connection_destroy_connection(struct nc_client_connection* conn);

// Internal only called from self
void nc_client_connection_dtls_closed_cb(const np_error_code ec, void* data);

/**
 * Get underlying DTLS connection from connection reference. Used by
 * nc_stream_manager.
 */
#if defined(NABTO_DEVICE_DTLS_CLIENT_ONLY)
struct np_dtls_cli_connection* nc_client_connection_get_dtls_connection(struct nc_client_connection* conn);
#else
struct np_dtls_srv_connection* nc_client_connection_get_dtls_connection(struct nc_client_connection* conn);
#endif
/**
 * Get client fingerprint from DTLS server. Used by API.
 */
np_error_code nc_client_connection_get_client_fingerprint(struct nc_client_connection* conn, uint8_t* fp);

/**
 * internal only called from self. Notifies nc_device of events.
 */
void nc_client_connection_event_listener_notify(struct nc_client_connection* conn, enum nc_connection_event event);

/**
 * Send data on the client connection
 */
np_error_code nc_client_connection_async_send_data(
    struct nc_client_connection* conn,
    struct np_dtls_send_context* sendCtx);

#endif //_NC_CLIENT_CONNECTION_H_
