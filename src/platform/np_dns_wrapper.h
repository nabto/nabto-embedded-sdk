#ifndef _NP_DNS_WRAPPER_H_
#define _NP_DNS_WRAPPER_H_

#include "interfaces/np_dns.h"

/**
 * Wrapper functions for dns resolving. See function definitions in
 * interfaces/np_dns.h for documentation of the functions.
 */
void np_dns_async_resolve_v4(struct np_dns* dns, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

void np_dns_async_resolve_v6(struct np_dns* dns, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

#endif
