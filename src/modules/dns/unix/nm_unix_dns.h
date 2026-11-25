#ifndef NP_UNIX_DNS_H_
#define NP_UNIX_DNS_H_

#include <platform/interfaces/np_dns.h>
#include <platform/np_types.h>

#include <nn/llist.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_unix_dns_resolver {
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    struct nn_llist events;
    // The request the resolver thread is resolving, if any.
    struct nm_dns_resolve_event* current;
    bool stopped;
};


struct np_dns nm_unix_dns_resolver_get_impl(struct nm_unix_dns_resolver* resolver);

/**
 * Initialize the dns resolver.
 */
np_error_code nm_unix_dns_resolver_init(struct nm_unix_dns_resolver* resolver);

/**
 * Stop the dns resolver. Outstanding requests are resolved with
 * NABTO_EC_STOPPED, also a request the resolver thread is busy with, its
 * result is dropped. No completion event is resolved after this call. Call
 * it from nabto_device_platform_stop_blocking.
 */
void nm_unix_dns_resolver_stop(struct nm_unix_dns_resolver* resolver);

/**
 * Deinitialize the dns resolver. Stops it and waits for the resolver thread.
 */
void nm_unix_dns_resolver_deinit(struct nm_unix_dns_resolver* resolver);

/**
 * Run the dns resolver
 */
void nm_unix_dns_resolver_run(struct nm_unix_dns_resolver* resolver);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // _NP_UNIX_DNS_H_
