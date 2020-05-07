#include "nm_libevent_dns.h"
#include <event2/dns.h>

#include <platform/np_ip_address.h>
#include <platform/np_dns.h>
#include <platform/np_platform.h>
#include <platform/np_completion_event.h>

#include <stdlib.h>
#include <string.h>

#define DNS_RECORDS_SIZE 4

struct nm_libevent_dns_module {
    struct event_base* eventBase;
};

struct np_dns_resolver {
    struct evdns_base* dnsBase;
};

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


static np_error_code create_resolver(struct np_platform* pl, struct np_dns_resolver** resolver);
static void destroy_resolver(struct np_dns_resolver* resolver);
static void stop_resolver(struct np_dns_resolver* resolver);
static void async_resolve_v4(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);
static void async_resolve_v6(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

void nm_libevent_dns_init(struct np_platform* pl, struct event_base *eventBase)
{
    struct nm_libevent_dns_module* module = calloc(1,sizeof(struct nm_libevent_dns_module));
    module->eventBase = eventBase;
    pl->dnsData = module;

    pl->dns.create_resolver = &create_resolver;
    pl->dns.destroy_resolver = &destroy_resolver;
    pl->dns.stop = &stop_resolver;
    pl->dns.async_resolve_v4 = &async_resolve_v4;
    pl->dns.async_resolve_v6 = &async_resolve_v6;
}

void nm_libevent_dns_deinit(struct np_platform* pl)
{
    if (pl->dnsData != NULL) {
        struct nm_libevent_dns_module* module = pl->dnsData;
        free(module);
    }
    pl->dnsData = NULL;
}

np_error_code create_resolver(struct np_platform* pl, struct np_dns_resolver** resolver)
{
    struct nm_libevent_dns_module* module = pl->dnsData;
    struct np_dns_resolver* r = calloc(1, sizeof(struct np_dns_resolver));
    r->dnsBase = evdns_base_new(module->eventBase, EVDNS_BASE_INITIALIZE_NAMESERVERS);
    *resolver = r;
    return NABTO_EC_OK;
}

void destroy_resolver(struct np_dns_resolver* resolver)
{
    stop_resolver(resolver);
    free(resolver);
}

void stop_resolver(struct np_dns_resolver* resolver)
{
    if (resolver->dnsBase == NULL) {
        return;
    }
    evdns_base_free(resolver->dnsBase, 1);
    resolver->dnsBase = NULL;
}

static void async_resolve_v4(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct evdns_base* dnsBase = resolver->dnsBase;
    int flags = 0;

    struct nm_dns_request* dnsRequest = calloc(1, sizeof(struct nm_dns_request));
    dnsRequest->completionEvent = completionEvent;
    dnsRequest->ips = ips;
    dnsRequest->ipsSize = ipsSize;
    dnsRequest->ipsResolved = ipsResolved;
    dnsRequest->req = evdns_base_resolve_ipv4(dnsBase, host, flags, dns_cb, dnsRequest);
}

static void async_resolve_v6(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct evdns_base* dnsBase = resolver->dnsBase;
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
