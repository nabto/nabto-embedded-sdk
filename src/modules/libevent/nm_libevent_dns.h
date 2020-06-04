#ifndef _NM_LIBEVENT_DNS_H_
#define _NM_LIBEVENT_DNS_H_

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct event_base;
struct nm_libevent_context;

struct np_dns nm_libevent_dns_create_impl(struct nm_libevent_context* ctx);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
