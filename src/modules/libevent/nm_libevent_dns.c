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

    struct nm_dns_request* dnsRequest = calloc(1, sizeof(struct nm_dns_request));
    dnsRequest->completionEvent = completionEvent;
    dnsRequest->ips = ips;
    dnsRequest->ipsSize = ipsSize;
    dnsRequest->ipsResolved = ipsResolved;
    dnsRequest->req = evdns_base_resolve_ipv4(dnsBase, host, flags, dns_cb, dnsRequest);
}

static void async_resolve_v6(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct nm_libevent_context* ctx = obj->data;
    struct evdns_base* dnsBase = ctx->dnsBase;
    int flags = 0;

    struct nm_dns_request* dnsRequest = calloc(1, sizeof(struct nm_dns_request));
    dnsRequest->completionEvent = completionEvent;
    dnsRequest->ips = ips;
    dnsRequest->ipsSize = ipsSize;
    dnsRequest->ipsResolved = ipsResolved;
    dnsRequest->req = evdns_base_resolve_ipv6(dnsBase, host, flags, dns_cb, dnsRequest);
}

void dns_cb(int result, char type, int count, int ttl, void *addresses, void *arg)
{
    struct nm_dns_request* ctx = arg;
    if (result != DNS_ERR_NONE) {
        np_completion_event_resolve(ctx->completionEvent, NABTO_EC_UNKNOWN);
        free(ctx);
        return;
    }

    int i;
    size_t resolved = 0;
    for (i = 0; i < count && resolved < ctx->ipsSize; i++) {
        if (type == DNS_IPv4_A) {
            ctx->ips[i].type = NABTO_IPV4;
            uint8_t* addressStart = ((uint8_t*)addresses) + i*4;
            memcpy(ctx->ips[resolved].ip.v4, addressStart, 4);
            resolved++;
        } else if (type == DNS_IPv6_AAAA) {
            ctx->ips[i].type = NABTO_IPV6;
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
