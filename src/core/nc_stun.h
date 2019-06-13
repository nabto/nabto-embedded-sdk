#ifndef NC_STUN_H
#define NC_STUN_H

#include <platform/np_platform.h>
#include <stun/nabto_stun_client.h>
#include <core/nc_udp_dispatch.h>

#ifndef NC_STUN_MAX_CALLBACKS
#define NC_STUN_MAX_CALLBACKS 10
#endif
#ifndef NC_STUN_MAX_ENDPOINTS
#define NC_STUN_MAX_ENDPOINTS 10
#endif
#ifndef NC_STUN_PORT
#define NC_STUN_PORT 3478
#endif

typedef void (*nc_stun_analyze_callback)(const np_error_code ec, const struct nabto_stun_result* res, void* data);

struct nc_stun_callback {
    nc_stun_analyze_callback cb;
    void* data;
};

enum nc_stun_state {
    NC_STUN_STATE_NONE = 0,
    NC_STUN_STATE_RUNNING,
    NC_STUN_STATE_DONE
};


struct nc_stun_context {
    struct np_platform* pl;
    struct nc_udp_dispatch_context* priUdp;
    struct nc_udp_dispatch_context* secUdp;
    struct nabto_stun stun;
    struct nabto_stun_module stunModule;

    struct nc_stun_callback cbs[NC_STUN_MAX_CALLBACKS];
    enum nc_stun_state state;
    np_error_code ec;
    const struct nabto_stun_result* res;
    const char* hostname;
    struct nabto_stun_endpoint eps[NC_STUN_MAX_ENDPOINTS];
    size_t numEps;
    struct np_event resultEv;
    struct np_timed_event toEv;

    np_communication_buffer* sendBuf;
    struct np_udp_endpoint sendEp;
    struct np_udp_send_context sendCtx;
};

void nc_stun_init(struct nc_stun_context* ctx,
                  struct np_platform* pl,
                  const char* hostname,
                  struct nc_udp_dispatch_context* udp,
                  struct nc_udp_dispatch_context* secondaryUdp);

np_error_code nc_stun_async_analyze(struct nc_stun_context* ctx,
                                    nc_stun_analyze_callback cb, void* data);

void nc_stun_handle_packet(struct nc_stun_context* ctx,
                           struct np_udp_endpoint ep,
                           np_communication_buffer* buffer,
                           uint16_t bufferSize);

uint16_t nc_stun_get_local_port(struct nc_stun_context* ctx);

#endif // NC_STUN_H
