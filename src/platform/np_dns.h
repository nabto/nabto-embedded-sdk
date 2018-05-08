#ifndef _NP_DNS_H_
#define _NP_DNS_H_

#ifndef NP_DNS_RESOLVED_IPS_MAX
#define NP_DNS_RESOLVED_IPS_MAX 4
#endif

typedef void (*np_dns_resolve_callback)(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data);

struct np_dns_module {
    /**
     * Resolve Hostname host
     * pl is pointer to a fully initialized np_platform
     */
    np_error_code (*async_resolve)(struct np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data);
};

#endif //_NP_DNS_H_
