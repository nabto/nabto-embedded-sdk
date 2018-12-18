#ifndef NC_ATTACHER_H
#define NC_ATTACHER_H

#include <platform/np_platform.h>
#include <core/nc_udp_dispatch.h>

#define LOAD_BALANCER_PORT 4433

// TODO: Move this definition to some configuration
#define NABTO_MAX_DR_EPS 2

typedef void (*nc_attached_callback)(const np_error_code ec, void* data);

// This should possibly use nc_attached_state instead of np_error_code
typedef void (*nc_detached_callback)(const np_error_code ec, void* data);

enum nc_attacher_state {
    NC_ATTACHER_RESOLVING_DNS,
    NC_ATTACHER_CONNECTING_TO_LB,
    NC_ATTACHER_CONNECTED_TO_LB,
    NC_ATTACHER_CONNECTING_TO_RELAY,
    NC_ATTACHER_CONNECTED_TO_RELAY,
    NC_ATTACHER_ATTACHED
};

struct nc_attach_dr_endpoint {
    uint16_t port;
    uint8_t az;
    uint8_t fp[16];
    char dns[256];
    uint8_t dnsLen;
};

struct nc_attach_send_data {
    np_dtls_cli_context* cryp;
    uint8_t chan;
    uint8_t* start;
    uint32_t size;
    np_dtls_send_to_callback cb;
    void* data;
    struct np_timed_event ev;
};

struct nc_attach_context {
    struct np_platform* pl;
    const struct nc_attach_parameters* params;
    struct nc_attach_send_data sendData;
    uint32_t sessionId;
    struct nc_attach_dr_endpoint drEps[NABTO_MAX_DR_EPS];
    uint8_t activeDrEps;
    nc_attached_callback cb;
    nc_detached_callback detachCb;
    void* detachCbData;
    struct nc_udp_dispatch_context* udp;
    void* cbData;
    np_udp_endpoint ep;
    np_dtls_cli_context* lbDtls;
    np_dtls_cli_context* drDtls;
    np_communication_buffer* buffer;
    char dns[256];
    uint8_t dnsLen;
    enum nc_attacher_state state;
    bool detaching;
};

struct nc_attach_parameters {
    const char* appName;
    const char* appVersion;
    const char* hostname;
    struct nc_udp_dispatch_context* udp;
};

np_error_code nc_attacher_async_attach(struct nc_attach_context* ctx,
                                       struct np_platform* pl,
                                       const struct nc_attach_parameters* params,
                                       nc_attached_callback cb, void* data);

np_error_code nc_attacher_register_detatch_callback(struct nc_attach_context* ctx,
                                                    nc_detached_callback cb, void* data);

np_error_code nc_attacher_detach(struct nc_attach_context* ctx);

#endif //NC_ATTACHER_H
