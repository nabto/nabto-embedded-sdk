#ifndef NC_DEVICE_H
#define NC_DEVICE_H

#include <core/nc_attacher.h>
#include <core/nc_stream_manager.h>
#include <core/nc_client_connection_dispatch.h>
#include <core/nc_stun.h>
#include <core/nc_coap_server.h>
#include <core/nc_stun_coap.h>
#include <core/nc_rendezvous_coap.h>
#include <core/nc_iam.h>
#include <core/nc_connection_event.h>
#include <modules/mdns/nm_mdns.h>

#include <platform/np_error_code.h>


typedef void (*nc_device_close_callback)(const np_error_code ec, void* data);

struct nc_device_context {
    struct np_platform* pl;
    bool stopping;
    bool clientConnsClosed;
    bool isDetached;

    struct nc_udp_dispatch_context udp;
    // this socket is used for the secondary stun socket.
    struct nc_udp_dispatch_context secondaryUdp;
    struct nc_attach_parameters attachParams;
    struct nc_attach_context attacher;
    struct nc_stream_manager_context streamManager;
    struct nc_client_connection_dispatch_context clientConnect;
    struct nc_stun_context stun;
    struct nc_coap_server_context coapServer;
    struct nc_coap_client_context coapClient;
    struct nc_rendezvous_context rendezvous;
    struct nc_stun_coap_context stunCoap;
    struct nc_rendezvous_coap_context rendezvousCoap;
    struct nc_iam iam;
    struct np_dtls_srv* dtlsServer;

    bool enableMdns;
    struct np_mdns_context* mdns;

    // unique connectionReference for each connection
    uint64_t connectionRef;

    const char* stunHost;
    const char* productId;
    const char* deviceId;

    uint16_t serverPort;

    struct np_timed_event tEv;
    struct np_event closeEvent;
    uint8_t attachAttempts;
    nc_device_close_callback closeCb;
    void* closeCbData;

    struct nc_connection_events_listener eventsListenerSentinel;
};

void nc_device_init(struct nc_device_context* dev, struct np_platform* pl);
void nc_device_deinit(struct nc_device_context* dev);

void nc_device_set_keys(struct nc_device_context* device, const unsigned char* publicKeyL, size_t publicKeySize, const unsigned char* privateKeyL, size_t privateKeySize);

np_error_code nc_device_start(struct nc_device_context* dev,
                              const char* appName, const char* appVersion,
                              const char* productId, const char* deviceId,
                              const char* hostname, const char* stunHost,
                              const uint16_t port, bool enableMdns);

np_error_code nc_device_close(struct nc_device_context* dev, nc_device_close_callback cb, void* data);

uint64_t nc_device_next_connection_ref(struct nc_device_context* dev);

uint64_t nc_device_get_connection_ref_from_stream(struct nc_device_context* dev, struct nabto_stream* stream);

struct nc_client_connection* nc_device_connection_from_ref(struct nc_device_context* dev, uint64_t ref);

bool nc_device_user_in_use(struct nc_device_context* dev, struct nc_iam_user* user);

void nc_device_add_connection_events_listener(struct nc_device_context* dev, struct nc_connection_events_listener* listener, nc_connection_event_callback cb, void* userData);
void nc_device_remove_connection_events_listener(struct nc_device_context* dev, struct nc_connection_events_listener* listener);

void nc_device_connection_events_listener_notify(struct nc_device_context* dev, uint64_t connectionRef, enum nc_connection_event event);

#endif // NC_DEVICE_H
