#ifndef _NM_LIBEVENT_H_
#define _NM_LIBEVENT_H_

#include <platform/np_communication_buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct event_base;

struct nm_libevent_context {
    bool stopped;
    struct event_base* eventBase;
    struct evdns_base* dnsBase;
};

void nm_libevent_global_init();
void nm_libevent_global_deinit();
bool nm_libevent_init(struct nm_libevent_context* ctx, struct event_base* eventBase);
void nm_libevent_stop(struct nm_libevent_context* ctx);
void nm_libevent_deinit(struct nm_libevent_context* ctx);

struct np_udp nm_libevent_udp_get_impl(struct nm_libevent_context* ctx);
struct np_tcp nm_libevent_tcp_get_impl(struct nm_libevent_context* ctx);
struct np_timestamp nm_libevent_timestamp_get_impl(struct nm_libevent_context* ctx);
struct np_local_ip nm_libevent_local_ip_get_impl(struct nm_libevent_context* ctx);
struct np_dns nm_libevent_dns_get_impl(struct nm_libevent_context* ctx);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
