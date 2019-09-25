#ifndef NC_ATTACHER_H
#define NC_ATTACHER_H

#include <platform/np_platform.h>
#include <core/nc_udp_dispatch.h>
#include <core/nc_coap_client.h>

#define LOAD_BALANCER_PORT 4433

// TODO: implement multi attach

// TODO: Move this definition to some configuration
#define NABTO_MAX_DR_EPS 2

typedef void (*nc_attached_callback)(const np_error_code ec, void* data);

// This should possibly use nc_attached_state instead of np_error_code
typedef void (*nc_detached_callback)(const np_error_code ec, void* data);

enum nc_attacher_state {
    NC_ATTACHER_RESOLVING_DNS,
    NC_ATTACHER_CONNECTING_TO_BS,
    NC_ATTACHER_CONNECTED_TO_BS,
    NC_ATTACHER_ATTACHED
};

struct nc_attach_dr_endpoint {
    uint16_t port;
    uint8_t az;
    uint8_t fp[16];
    char dns[256];
    uint8_t dnsLen;
};

struct nc_attach_context {
    struct np_platform* pl;
    struct nc_device_context* device;
    const struct nc_attach_parameters* params;
    uint32_t sessionId;
    nc_attached_callback cb;
    nc_detached_callback detachCb;
    void* detachCbData;
    struct nc_udp_dispatch_context* udp;
    struct np_udp_send_context sendCtx;
    void* cbData;
    np_udp_endpoint ep;
    np_dtls_cli_context* dtls;
    char dns[256];
    uint8_t dnsLen;
    enum nc_attacher_state state;
    bool detaching;
    struct nc_coap_client_context* coapClient;

    struct nc_keep_alive_context keepAlive;
    struct np_dtls_cli_send_context keepAliveSendCtx;
};

struct nc_attach_parameters {
    const char* appName;
    const char* appVersion;
    const char* hostname;
    struct nc_udp_dispatch_context* udp;
};

void nc_attacher_init(struct nc_attach_context* ctx, struct np_platform* pl, struct nc_device_context* device, struct nc_coap_client_context* coapClient);
void nc_attacher_deinit(struct nc_attach_context* ctx);

np_error_code nc_attacher_set_keys(struct nc_attach_context* ctx,
                                   const unsigned char* publicKeyL, size_t publicKeySize,
                                   const unsigned char* privateKeyL, size_t privateKeySize);

np_error_code nc_attacher_async_attach(struct nc_attach_context* ctx,
                                       struct np_platform* pl,
                                       const struct nc_attach_parameters* params,
                                       nc_attached_callback cb, void* data);

np_error_code nc_attacher_register_detach_callback(struct nc_attach_context* ctx,
                                                   nc_detached_callback cb, void* data);

np_error_code nc_attacher_detach(struct nc_attach_context* ctx);

#endif //NC_ATTACHER_H
