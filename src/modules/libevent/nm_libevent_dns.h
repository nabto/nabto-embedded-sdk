#ifndef _NM_LIBEVENT_DNS_H_
#define _NM_LIBEVENT_DNS_H_

#include <stdbool.h>
#include <nn/llist.h>
#include <platform/np_error_code.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_libevent_dns {
    bool stopped;
    struct event_base* eventBase;
    struct evdns_base* dnsBase;
    struct nn_llist requests;
};

np_error_code nm_libevent_dns_init(struct nm_libevent_dns* ctx, struct event_base* eventBase);

void nm_libevent_dns_stop(struct nm_libevent_dns* ctx);

void nm_libevent_dns_deinit(struct nm_libevent_dns* ctx);

struct np_dns nm_libevent_dns_get_impl(struct nm_libevent_dns* ctx);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
