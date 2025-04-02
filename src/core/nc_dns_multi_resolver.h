#ifndef _NC_DNS_MULTI_RESOLVER_H_
#define _NC_DNS_MULTI_RESOLVER_H_

#include <platform/np_completion_event.h>
#include <platform/np_ip_address.h>
#include <platform/np_error_code.h>
#include <platform/interfaces/np_dns.h>

/**
 * Resolves ipv4 and ipv6 addresses and builds an array of the
 * resulting addresses with alternating ipv4 and ipv6 addresses.
 */

#define NC_DNS_MULTI_RESOLVER_MAX_IPS 4



struct nc_dns_multi_resolver_context {
    struct np_platform* pl;
    struct np_ip_address v4Ips[NC_DNS_MULTI_RESOLVER_MAX_IPS];
    struct np_ip_address v6Ips[NC_DNS_MULTI_RESOLVER_MAX_IPS];
    size_t v4IpsSize;
    size_t v6IpsSize;
    np_error_code v4Ec;
    np_error_code v6Ec;
    struct np_completion_event v4CompletionEvent;
    struct np_completion_event v6CompletionEvent;
    const char* host;

    // output from the resolving.
    struct np_ip_address* ips;
    size_t ipsSize;
    size_t* ipsResolved;
    struct np_completion_event* resolvedCompletionEvent;
};

np_error_code nc_dns_multi_resolver_init(struct np_platform* pl, struct nc_dns_multi_resolver_context* ctx);

void nc_dns_multi_resolver_deinit(struct nc_dns_multi_resolver_context* ctx);

void nc_dns_multi_resolver_resolve(struct nc_dns_multi_resolver_context* ctx, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* event);

#endif
