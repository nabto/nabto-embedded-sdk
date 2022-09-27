#ifndef NC_STUN_H
#define NC_STUN_H

#include <platform/np_platform.h>
#include <platform/np_completion_event.h>
#include <stun/nabto_stun_client.h>

#include <core/nc_udp_dispatch.h>
#include <core/nc_dns_multi_resolver.h>
#include <nn/ip_address.h>


#ifdef __cplusplus
extern "C" {
#endif


#ifndef NC_STUN_MAX_CALLBACKS
#define NC_STUN_MAX_CALLBACKS 10
#endif
#ifndef NC_STUN_MAX_ENDPOINTS
#define NC_STUN_MAX_ENDPOINTS 10
#endif
#ifndef NC_STUN_PORT
#define NC_STUN_PORT 3478
#endif

struct nc_device_context;

typedef void (*nc_stun_analyze_callback)(const np_error_code ec, const struct nabto_stun_result* res, void* data);

struct nc_stun_callback {
    struct nn_llist_node callbackNode;
    nc_stun_analyze_callback cb;
    void* data;
};

enum nc_stun_state {
    NC_STUN_STATE_NONE = 0,
    NC_STUN_STATE_RUNNING,
    NC_STUN_STATE_DONE,
    NC_STUN_STATE_ABORTED
};

struct nc_stun_context {
    bool initialized;
    struct np_platform* pl;
    struct nc_udp_dispatch_context* priUdp;
    struct nc_udp_dispatch_context* secUdp;
    struct nabto_stun stun;
    struct nabto_stun_module stunModule;

    // list of callbacks once a result is known
    struct nn_llist cbs;

    enum nc_stun_state state;
    np_error_code ec;
    const struct nabto_stun_result* res;
    const char* hostname;
    uint16_t priPort;
    struct nn_endpoint eps[NC_STUN_MAX_ENDPOINTS];
    size_t numEps;
    struct np_event* toEv;

    struct np_communication_buffer* sendBuf;
    struct np_udp_endpoint sendEp;
    struct np_completion_event sendCompletionEvent;
    bool simple;

    struct nc_dns_multi_resolver_context dnsMultiResolver;
    struct np_ip_address resolvedIps[NC_STUN_MAX_ENDPOINTS];
    size_t resolvedIpsSize;
    struct np_completion_event dnsCompletionEvent;
};

np_error_code nc_stun_init(struct nc_stun_context *ctx,
                           struct nc_device_context *device,
                           struct np_platform *pl);

void nc_stun_stop(struct nc_stun_context* ctx);

void nc_stun_set_sockets(struct nc_stun_context* ctx, struct nc_udp_dispatch_context* udp, struct nc_udp_dispatch_context* secondaryUdp);

void nc_stun_set_host(struct nc_stun_context* ctx, const char* hostname, uint16_t port);

void nc_stun_remove_sockets(struct nc_stun_context* ctx);

void nc_stun_deinit(struct nc_stun_context* ctx);

np_error_code nc_stun_async_analyze_simple(struct nc_stun_context* ctx, struct nc_stun_callback* callback,
                                           nc_stun_analyze_callback cb, void* data);

void nc_stun_handle_packet(struct nc_stun_context* ctx,
                           struct np_udp_endpoint* ep,
                           uint8_t* buffer,
                           uint16_t bufferSize);

uint16_t nc_stun_get_local_port(struct nc_stun_context* ctx);

void nc_stun_convert_ep(const struct nn_endpoint* stunEp, struct np_udp_endpoint* npEp );

#ifdef __cplusplus
} // extern c
#endif

#endif // NC_STUN_H
