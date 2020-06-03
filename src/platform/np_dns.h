#ifndef _NP_DNS_H_
#define _NP_DNS_H_

#ifndef NP_DNS_RESOLVED_IPS_MAX
#define NP_DNS_RESOLVED_IPS_MAX 4
#endif

#include <platform/np_error_code.h>
#include <platform/np_ip_address.h>
#include <nabto_types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct np_completion_event;
struct np_dns_resolver;
struct np_dns_functions;

struct np_dns {
    const struct np_dns_functions* vptr;
    void* data;
};

struct np_dns_functions {
    /**
     * Create a new resolver. A resolver can be used to resolve either
     * ipv4 or ipv6 addresses.
     *
     * @param pl  The platform
     * @param resolver  The resulting resolver.
     * @return NABTO_EC_OK  iff the object is created.
     */
    np_error_code (*create_resolver)(void* data, struct np_dns_resolver** resolver);

    /**
     * Destroy a resolver.
     *
     * @param resolver  The resolver to destroy.
     */
    void (*destroy_resolver)(struct np_dns_resolver* resolver);

    /**
     * stop a resolver. Stopping a resolver makes all the outstanding
     * dns requests stop.
     *
     * @param resolver  The resolver to stop.
     */
    void (*stop)(struct np_dns_resolver* resolver);

    /**
     * Resolve ipv4 addresses for the host name.
     *
     * The completion event shall be resolved when the dns resolution
     * has either failed or succeeded.
     *
     * @param resolver  The resolver
     * @param host  The host to resolve.
     * @param ips  The array to store the resolved ips in.
     * @param ipsSize  The size of the ips array.
     * @param ipsResolved  The number of ips put in the the ips array.
     * @param completionEvent  The completion event.
     */
    void (*async_resolve_v4)(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

    /**
     * Resolve ipv6 addresses for the host name.
     *
     * The completion event shall be resolved when the dns resolution
     * has either failed or succeeded.
     *
     * @param resolver  The resolver
     * @param host  The host to resolve.
     * @param ips  The array to store the resolved ips in.
     * @param ipsSize  The size of the ips array.
     * @param ipsResolved  The number of ips put in the the ips array.
     * @param completionEvent  The completion event.
     */
    void (*async_resolve_v6)(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

};

#ifdef __cplusplus
} //extern "C"
#endif

#endif //_NP_DNS_H_
