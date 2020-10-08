#ifndef NC_CLIENT_CONNECTION_H
#define NC_CLIENT_CONNECTION_H

#include <platform/np_platform.h>
#include <platform/np_completion_event.h>
#include <core/nc_stream_manager.h>
#include <core/nc_coap_server.h>
#include <core/nc_keep_alive.h>
#include <core/nc_connection_event.h>

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

enum nc_spake2_state {
    NC_SPAKE2_STATE_INIT,
    NC_SPAKE2_STATE_WAIT_PASSWORD,
    NC_SPAKE2_STATE_WAIT_CONFIRMATION,
    NC_SPAKE2_STATE_AUTHENTICATED,
    NC_SPAKE2_STATE_ERROR
};

struct nc_client_connection {
    struct nn_llist_node connectionsNode;
    struct np_platform* pl;
    struct np_dtls_srv_connection* dtls;
    struct nc_client_connection_dispatch_context* dispatch;
    struct nc_stream_manager_context* streamManager;
    struct nc_stun_context* stun;
    struct nc_connection_id id;
    struct nc_connection_channel currentChannel;
    struct nc_connection_channel alternativeChannel;
    uint64_t currentMaxSequence;
    struct nc_device_context* device;

    np_dtls_srv_send_callback sentCb;
    void* sentData;
    uint64_t connectionRef;
    struct np_completion_event sendCompletionEvent;

    struct nc_keep_alive_context keepAlive;
    struct np_dtls_srv_send_context keepAliveSendCtx;

    bool hasSpake2Key;  // true iff the key has been set
    uint8_t spake2Key[32];
    bool passwordAuthenticated; // true iff some password authentication request has succeeded on the connection.
    size_t passwordAuthenticationRequests;
};

/**
 * Open new client connection. Called by nc_client_connection_dispatch
 * when client hello arrives on unknown connection id.
 *
 * Initializes client connection, creates a DTLS Server connection,
 * and forwards the hello packet to DTLS.
 */
np_error_code nc_client_connection_open(struct np_platform* pl, struct nc_client_connection* conn,
                                     struct nc_client_connection_dispatch_context* dispatch,
                                     struct nc_device_context* device,
                                     struct nc_udp_dispatch_context* sock, struct np_udp_endpoint* ep,
                                     uint8_t* buffer, uint16_t bufferSize);

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

// TODO: seems unused
void nc_client_connection_dtls_recv_callback(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                                          uint8_t* buffer, uint16_t bufferSize, void* data);

// Internal only called from self
void nc_client_connection_dtls_closed_cb(const np_error_code ec, void* data);

/**
 * Get underlying DTLS connection from connection reference. Used by
 * nc_stream_manager.
 */
struct np_dtls_srv_connection* nc_client_connection_get_dtls_connection(struct nc_client_connection* conn);

/**
 * Get client fingerprint from DTLS server. Used by API.
 */
np_error_code nc_client_connection_get_client_fingerprint(struct nc_client_connection* conn, uint8_t* fp);

/**
 * Get device fingerprint from DTLS server.
 */
np_error_code nc_client_connection_get_device_fingerprint(struct nc_client_connection* conn, uint8_t* fp);

/**
 * Query if connection uses local socket or not. Used by API.
 */
bool nc_client_connection_is_local(struct nc_client_connection* conn);

/**
 * Query if the connection is password authenticated or not. Used by API.
 */
bool nc_client_connection_is_password_authenticated(struct nc_client_connection* conn);

/**
 * internal only called from self. Notifies nc_device of events.
 */
void nc_client_connection_event_listener_notify(struct nc_client_connection* conn, enum nc_connection_event event);

#endif //_NC_CLIENT_CONNECTION_H_
