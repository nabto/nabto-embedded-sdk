#ifndef _NM_LIBEVENT_H_
#define _NM_LIBEVENT_H_

#include <platform/np_communication_buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct event_base;

struct nm_libevent_context {
    struct event_base* eventBase;
    struct evdns_base* dnsBase;
};

void nm_libevent_global_init();
void nm_libevent_global_deinit();
void nm_libevent_init(struct nm_libevent_context* ctx, struct event_base* eventBase);
void nm_libevent_deinit(struct nm_libevent_context* ctx);

void nm_libevent_udp_init(struct np_platform* pl, struct nm_libevent_context* ctx);

struct np_udp nm_libevent_create_udp(struct nm_libevent_context* ctx);
struct np_tcp nm_libevent_create_tcp(struct nm_libevent_context* ctx);
struct np_timestamp nm_libevent_create_timestamp(struct nm_libevent_context* ctx);
struct np_local_ip nm_libevent_create_local_ip(struct nm_libevent_context* ctx);
struct np_dns nm_libevent_dns_create_impl(struct nm_libevent_context* ctx);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
