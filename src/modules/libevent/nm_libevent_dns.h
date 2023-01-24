#ifndef _NM_LIBEVENT_DNS_H_
#define _NM_LIBEVENT_DNS_H_

#include <stdbool.h>
#include <nn/llist.h>
#include <platform/np_error_code.h>
#include <platform/interfaces/np_event_queue.h>
#include <api/nabto_device_threads.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_libevent_dns {
    bool stopped;
    struct event_base* eventBase;
    struct evdns_base* dnsBase;
    struct nn_llist requests;
    struct nabto_device_mutex* mutex;
    struct nabto_device_mutex* cancelMutex;
    struct np_event_queue eq;
};

np_error_code nm_libevent_dns_init(struct nm_libevent_dns* ctx, struct event_base* eventBase, struct nabto_device_mutex* coreMutex, struct np_event_queue* eq);

void nm_libevent_dns_stop(struct nm_libevent_dns* ctx);

void nm_libevent_dns_deinit(struct nm_libevent_dns* ctx);

struct np_dns nm_libevent_dns_get_impl(struct nm_libevent_dns* ctx);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
