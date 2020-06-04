#ifndef _NP_UNIX_DNS_H_
#define _NP_UNIX_DNS_H_

#include <platform/interfaces/np_dns.h>
#include <nabto_types.h>

#include <pthread.h>
#include <nn/llist.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_unix_dns_resolver {
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    struct nn_llist events;
    bool stopped;
};


struct np_dns nm_unix_dns_create(struct nm_unix_dns_resolver* resolver);

np_error_code nm_unix_dns_resolver_init(struct nm_unix_dns_resolver* resolver);
void nm_unix_dns_resolver_deinit(struct nm_unix_dns_resolver* resolver);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // _NP_UNIX_DNS_H_
