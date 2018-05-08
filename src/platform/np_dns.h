#ifndef _NP_DNS_H_
#define _NP_DNS_H_

#ifndef NP_DNS_RESOLVED_IPS_MAX
#define NP_DNS_RESOLVED_IPS_MAX 4
#endif

struct np_dns_ctx {
    struct np_event ev;
    const char* host;
    struct np_dns_record* rec;
    np_dns_resolve_callback cb;
    np_error_code ec;
    void* data;
};

struct np_dns_record {
    struct np_ip_address ips[NP_DNS_RESOLVED_IPS_MAX];
};

typedef void (*np_dns_resolve_callback)(const np_error_code ec, struct np_dns_record* rec, void* data);

struct np_dns_module {
    /**
     * Resolve Hostname host
     * pl is pointer to a fully initialized np_platform
     * ctx must be allocated by the caller, but may otherwise be left uninitialized
     */
    void (*async_resolve)(struct np_platform* pl, struct np_dns_ctx* ctx, const char* host, np_dns_resolve_callback cb, void* data);
}

#endif //_NP_DNS_H_
