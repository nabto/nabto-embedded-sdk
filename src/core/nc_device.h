#ifndef NC_DEVICE_H
#define NC_DEVICE_H

#include <core/nc_attacher.h>
#include <core/nc_stream_manager.h>
#include <core/nc_client_connect_dispatch.h>
#include <core/nc_stun.h>
#include <core/nc_coap_server.h>
#include <core/nc_stun_coap.h>
#include <core/nc_rendezvous_coap.h>

#include <platform/np_error_code.h>

typedef void (*nc_device_close_callback)(const np_error_code ec, void* data);

struct nc_device_context {
    struct np_platform* pl;
    bool stopping;
    struct nc_udp_dispatch_context udp;
    // this socket is used for the secondary stun socket.
    struct nc_udp_dispatch_context secondaryUdp;
    struct nc_attach_parameters attachParams;
    struct nc_attach_context attacher;
    struct nc_stream_manager_context streamManager;
    struct nc_client_connect_dispatch_context clientConnect;
    struct nc_stun_context stun;
    struct nc_coap_server_context coap;
    struct nc_rendezvous_context rendezvous;
    struct nc_stun_coap_context stunCoap;
    struct nc_rendezvous_coap_context rendezvousCoap;

    const char* stunHost;

    struct np_timed_event tEv;
    uint8_t attachAttempts;
    nc_device_close_callback closeCb;
    void* closeCbData;
};

np_error_code nc_device_start(struct nc_device_context* dev, struct np_platform* pl,
                              const char* appName, const char* appVersion,
                              const char* productId, const char* deviceId,
                              const char* hostname, const char* stunHost,
                              const uint16_t port);

np_error_code nc_device_close(struct nc_device_context* dev, nc_device_close_callback cb, void* data);

#endif // NC_DEVICE_H
