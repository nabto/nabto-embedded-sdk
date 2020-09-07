#ifndef NC_DEVICE_H
#define NC_DEVICE_H

#include <core/nc_device_defines.h>
#include <core/nc_attacher.h>
#include <core/nc_stream_manager.h>
#include <core/nc_client_connection_dispatch.h>
#include <core/nc_stun.h>
#include <core/nc_coap_server.h>
#include <core/nc_stun_coap.h>
#include <core/nc_rendezvous_coap.h>
#include <core/nc_connection_event.h>
#include <core/nc_spake2.h>
#include <core/nc_rendezvous.h>

#include <platform/np_error_code.h>

#include <nn/string_set.h>
#include <nn/string_map.h>

enum nc_device_state {
    NC_DEVICE_STATE_SETUP,
    NC_DEVICE_STATE_RUNNING,
    NC_DEVICE_STATE_STOPPED
};

typedef void (*nc_device_event_callback)(enum nc_device_event event, void* userData);

struct nc_device_events_listener {
    struct nn_llist_node eventsListenersNode;

    nc_device_event_callback cb;
    void* userData;
};

typedef void (*nc_device_close_callback)(const np_error_code ec, void* data);

struct nc_device_context {
    struct np_platform* pl;
    enum nc_device_state state;
    bool clientConnsClosed;
    bool isDetached;

    // This is the main socket
    struct nc_udp_dispatch_context udp;
    // this socket is used for the secondary stun socket.
    struct nc_udp_dispatch_context secondaryUdp;
    // This socket is used for local client connections
    struct nc_udp_dispatch_context localUdp;

    struct nc_attach_context attacher;
    struct nc_stream_manager_context streamManager;
    struct nc_client_connection_dispatch_context clientConnect;
    struct nc_stun_context stun;
    struct nc_coap_server_context coapServer;
    struct nc_coap_client_context coapClient;
    struct nc_rendezvous_context rendezvous;
    struct nc_stun_coap_context stunCoap;
    struct nc_rendezvous_coap_context rendezvousCoap;
    struct np_dtls_srv* dtlsServer;

    bool enableMdns;
    struct np_mdns_context* mdns;

    struct nn_string_set mdnsSubtypes;
    struct nn_string_map mdnsTxtItems;
    char* mdnsInstanceName;

    // unique connectionReference for each connection
    uint64_t connectionRef;

    const char* stunHost;
    uint16_t stunPort;
    const char* productId;
    const char* deviceId;
    const char* hostname;

    uint16_t serverPort;

    // Ports to bind the sockets to.
    uint16_t localPort;
    uint16_t p2pPort;

    nc_device_close_callback closeCb;
    void* closeCbData;

    struct nn_llist eventsListeners;
    struct nn_llist deviceEvents;
    struct np_completion_event socketBoundCompletionEvent;
    struct nc_spake2_module spake2;
};

np_error_code nc_device_init(struct nc_device_context* dev, struct np_platform* pl);
void nc_device_deinit(struct nc_device_context* dev);

void nc_device_set_keys(struct nc_device_context* device, const unsigned char* publicKeyL, size_t publicKeySize, const unsigned char* privateKeyL, size_t privateKeySize);

np_error_code nc_device_start(struct nc_device_context* dev,
                              const char* appName, const char* appVersion,
                              const char* productId, const char* deviceId,
                              const char* hostname);

void nc_device_stop(struct nc_device_context* dev);

np_error_code nc_device_close(struct nc_device_context* dev, nc_device_close_callback cb, void* data);

np_error_code nc_device_next_connection_ref(struct nc_device_context* dev, uint64_t* ref);

uint64_t nc_device_get_connection_ref_from_stream(struct nc_device_context* dev, struct nabto_stream* stream);

struct nc_client_connection* nc_device_connection_from_ref(struct nc_device_context* dev, uint64_t ref);

void nc_device_add_connection_events_listener(struct nc_device_context* dev, struct nc_connection_events_listener* listener, nc_connection_event_callback cb, void* userData);
void nc_device_remove_connection_events_listener(struct nc_device_context* dev, struct nc_connection_events_listener* listener);
void nc_device_connection_events_listener_notify(struct nc_device_context* dev, uint64_t connectionRef, enum nc_connection_event event);

void nc_device_add_device_events_listener(struct nc_device_context* dev, struct nc_device_events_listener* listener, nc_device_event_callback cb, void* userData);
void nc_device_remove_device_events_listener(struct nc_device_context* dev, struct nc_device_events_listener* listener);
void nc_device_events_listener_notify(enum nc_device_event event, void* data);

np_error_code nc_device_add_server_connect_token(struct nc_device_context* ctx, const char* token);
np_error_code nc_device_is_server_connect_tokens_synchronized(struct nc_device_context* ctx);


#endif // NC_DEVICE_H
