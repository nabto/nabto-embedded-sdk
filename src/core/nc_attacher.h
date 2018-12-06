#ifndef NC_ATTACHER_H
#define NC_ATTACHER_H

#include <platform/np_platform.h>

#define LOAD_BALANCER_PORT 4433

// TODO: Move this definition to some configuration
#define NABTO_MAX_DR_EPS 2

typedef void (*nc_attached_callback)(const np_error_code ec, void* data);

// This should possibly use nc_attached_state instead of np_error_code
typedef void (*nc_detached_callback)(const np_error_code ec, void* data);

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
    np_udp_socket* sock;
    void* cbData;
    np_connection lbConn;
    np_connection drConn;
    np_dtls_cli_context* lbDtls;
    np_dtls_cli_context* drDtls;
    np_communication_buffer* buffer;
    struct np_connection_id id;
    struct np_connection_channel drChannel;
    struct np_connection_channel lbChannel;
    char dns[256];
    uint8_t dnsLen;
};

struct nc_attach_parameters {
    const char* appName;
    uint8_t appNameLength;
    const char* appVersion;
    uint8_t appVersionLength;
    const char* hostname;
    uint8_t hostnameLength;
};

np_error_code nc_attacher_async_attach(struct nc_attach_context* ctx, struct np_platform* pl, const struct nc_attach_parameters* params, nc_attached_callback cb, void* data);

np_error_code nc_attacher_register_detatch_callback(struct nc_attach_context* ctx, nc_detached_callback cb, void* data);

#endif //NC_ATTACHER_H
