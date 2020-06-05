#include "np_dns_wrapper.h"

void np_dns_async_resolve_v4(struct np_dns* dns, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    return dns->vptr->async_resolve_v4(dns, host, ips, ipsSize, ipsResolved, completionEvent);
}

void np_dns_async_resolve_v6(struct np_dns* dns, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    return dns->vptr->async_resolve_v6(dns, host, ips, ipsSize, ipsResolved, completionEvent);
}
