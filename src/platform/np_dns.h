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

typedef void (*np_dns_resolve_callback)(const np_error_code ec, struct np_ip_address* v4Rec, size_t v4RecSize, struct np_ip_address* v6Rec, size_t v6RecSize, void* data);

struct np_dns_module {
    /**
     * Resolve Hostname host
     * pl is pointer to a fully initialized np_platform
     */
    np_error_code (*async_resolve)(struct np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data);
};

struct np_dns_resolver;

struct np_dns_module_alt1 {
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

struct np_dns_module_alt2 {
    /**
     * In alternative 2, cancellation of outstanding dns requests is
     * made through the platform by calling a stop function on the dns
     * implementation
     */

    /**
     * Resolve ipv4 addresses for the host name.
     */
    void (*async_resolve_v4)(struct np_platform* pl, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

    /**
     * Resolve ipv6 addresses for the host name.
     */
    void (*async_resolve_v6)(struct np_platform* pl, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

};

struct np_dns_module_alt3 {
    /**
     * In alternative 3, cancellation of outstanding dns requests is
     * made through the platform by calling a stop function on the dns
     * implementation
     */

    /**
     * Resolve ip addresses for the host name.
     */
    void (*async_resolve)(struct np_platform* pl, const char* host, struct np_ip_address* v4ips, size_t v4ipsSize, size_t* v4ipsResolved, struct np_ip_address* v6ips, size_t v6ipsSize, size_t* v6ipsResolved, struct np_completion_event* completionEvent);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif //_NP_DNS_H_
