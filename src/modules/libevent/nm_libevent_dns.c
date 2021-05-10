#include "nm_libevent.h"
#include <event2/dns.h>

#include <platform/np_ip_address.h>
#include <platform/interfaces/np_dns.h>
#include <platform/np_platform.h>
#include <platform/np_completion_event.h>

#include <stdlib.h>
#include <string.h>

#define DNS_RECORDS_SIZE 4

struct nm_dns_request {
    struct np_platform* pl;
    struct evdns_request* request;
    struct np_completion_event* completionEvent;
    struct np_ip_address* ips;
    struct evdns_request* req;
    struct evdns_base* dnsBase;
    size_t ipsSize;
    size_t* ipsResolved;
};

static void dns_cb(int result, char type, int count, int ttl, void *addresses, void *arg);


static void async_resolve_v4(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);
static void async_resolve_v6(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

static struct np_dns_functions module = {
    &async_resolve_v4,
    &async_resolve_v6
};

struct np_dns nm_libevent_dns_get_impl(struct nm_libevent_context* ctx)
{
    struct np_dns obj;
    obj.mptr = &module;
    obj.data = ctx;
    return obj;
}

static void async_resolve_v4(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct nm_libevent_context* ctx = obj->data;
    struct evdns_base* dnsBase = ctx->dnsBase;
    int flags = 0;

    if (ipsSize == 0) {
        np_completion_event_resolve(completionEvent, NABTO_EC_NO_DATA);
        return;
    }

    {
        struct in6_addr dst;
        if (evutil_inet_pton(AF_INET6, host, &dst) == 1) {
            // this is an ipv6 address do not try to resolve it as ipv4.
            np_completion_event_resolve(completionEvent, NABTO_EC_NO_DATA);
            return;
        }
    }

    {
        struct in_addr dst;
        if (evutil_inet_pton(AF_INET, host, &dst) == 1) {
            // this is an ipv4 address do not try to resolve it as ipv6.
            ips[0].type = NABTO_IPV4;
            memcpy(ips[0].ip.v4, &dst, 4);
            *ipsResolved = 1;
            np_completion_event_resolve(completionEvent, NABTO_EC_OK);
            return;
        }
    }

    struct nm_dns_request* dnsRequest = calloc(1, sizeof(struct nm_dns_request));
    dnsRequest->completionEvent = completionEvent;
    dnsRequest->ips = ips;
    dnsRequest->ipsSize = ipsSize;
    dnsRequest->ipsResolved = ipsResolved;
    dnsRequest->dnsBase = dnsBase;
    dnsRequest->req = evdns_base_resolve_ipv4(dnsBase, host, flags, dns_cb, dnsRequest);
}

static void async_resolve_v6(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct nm_libevent_context* ctx = obj->data;
    struct evdns_base* dnsBase = ctx->dnsBase;
    int flags = 0;

    if (ipsSize == 0) {
        np_completion_event_resolve(completionEvent, NABTO_EC_NO_DATA);
        return;
    }

    {
        struct in_addr dst;
        if (evutil_inet_pton(AF_INET, host, &dst) == 1) {
            // this is an ipv4 address do not try to resolve it as ipv6.
            np_completion_event_resolve(completionEvent, NABTO_EC_NO_DATA);
            return;
        }
    }

    {
        struct in6_addr dst;
        if (evutil_inet_pton(AF_INET6, host, &dst) == 1) {
            // this is an ipv6 address just resolve it as such.
            ips[0].type = NABTO_IPV6;
            memcpy(ips[0].ip.v6, &dst, 16);
            *ipsResolved = 1;
            np_completion_event_resolve(completionEvent, NABTO_EC_OK);
            return;
        }
    }

    struct nm_dns_request* dnsRequest = calloc(1, sizeof(struct nm_dns_request));
    dnsRequest->completionEvent = completionEvent;
    dnsRequest->ips = ips;
    dnsRequest->ipsSize = ipsSize;
    dnsRequest->ipsResolved = ipsResolved;
    dnsRequest->dnsBase = dnsBase;
    dnsRequest->req = evdns_base_resolve_ipv6(dnsBase, host, flags, dns_cb, dnsRequest);
}

void dns_cb(int result, char type, int count, int ttl, void *addresses, void *arg)
{
    struct nm_dns_request* ctx = arg;

    if (result == DNS_ERR_TIMEOUT) {
        // maybe the system has changed nameservers, reload them
        struct evdns_base* base = ctx->dnsBase;
#ifdef _WIN32
        evdns_base_clear_host_addresses(base);
        evdns_base_config_windows_nameservers(base);
#else
        evdns_base_clear_host_addresses(base);
        evdns_base_resolv_conf_parse(base, DNS_OPTION_NAMESERVERS, "/etc/resolv.conf");
#endif
    }

    if (result != DNS_ERR_NONE) {
        np_completion_event_resolve(ctx->completionEvent, NABTO_EC_UNKNOWN);
        free(ctx);
        return;
    }

    int i;
    size_t resolved = 0;
    for (i = 0; i < count && resolved < ctx->ipsSize; i++) {
        if (type == DNS_IPv4_A) {
            ctx->ips[resolved].type = NABTO_IPV4;
            uint8_t* addressStart = ((uint8_t*)addresses) + i*4;
            memcpy(ctx->ips[resolved].ip.v4, addressStart, 4);
            resolved++;
        } else if (type == DNS_IPv6_AAAA) {
            ctx->ips[resolved].type = NABTO_IPV6;
            uint8_t* addressStart = ((uint8_t*)addresses) + i*16;
            memcpy(ctx->ips[resolved].ip.v6, addressStart, 16);
            resolved++;
        }
    }
    if (resolved == 0) {
        np_completion_event_resolve(ctx->completionEvent, NABTO_EC_NO_DATA);
    } else {
        *ctx->ipsResolved = resolved;
        np_completion_event_resolve(ctx->completionEvent, NABTO_EC_OK);
    }
    free(ctx);
}
