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

struct np_dns_module {
    /**
     * Create a new resolver. A resolver can be used to resolve either
     * ipv4 or ipv6 addresses.
     */
    np_error_code (*create_resolver)(struct np_platform* pl, struct np_dns_resolver** resolver);

    /**
     * Destroy a resolver.
     */
    void (*destroy_resolver)(struct np_dns_resolver* resolver);

    /**
     * stop a resolver
     */
    void (*stop)(struct np_dns_resolver* resolver);

    /**
     * Resolve ipv4 addresses for the host name.
     */
    void (*async_resolve_v4)(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

    /**
     * Resolve ipv6 addresses for the host name.
     */
    void (*async_resolve_v6)(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

};

#ifdef __cplusplus
} //extern "C"
#endif

#endif //_NP_DNS_H_
