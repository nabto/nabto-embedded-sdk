#include "nm_libevent_dns.h"
#include <event2/dns.h>

#include <platform/np_ip_address.h>
#include <platform/interfaces/np_dns.h>
#include <platform/np_platform.h>
#include <platform/np_completion_event.h>
#include <platform/np_error_code.h>


#include <platform/np_allocator.h>
#include <platform/np_logging.h>


#include <string.h>

#ifdef HAVE_WINDOWS_H
#include <winsock2.h>
#include <Ws2tcpip.h>
#endif

#define LOG NABTO_LOG_MODULE_PLATFORM

#define DNS_RECORDS_SIZE 4

struct nm_dns_request {
    struct evdns_getaddrinfo_request* req;

    // completion event to send the result back to the async_resolve_v4|6 caller.
    struct np_completion_event* completionEvent;

    // sometims the dns_cb in libevent 2.1.12 is called synchroniously. This
    // event makes sure that the callback is always deferred from the calls to
    // async_resolve_v4|6
    struct np_completion_event dnsCbDeZalgo;
    int cbResult;
    struct evutil_addrinfo* cbRes;

    struct np_ip_address* ips;
    struct nm_libevent_dns* moduleContext;
    size_t ipsSize;
    size_t* ipsResolved;
    struct nn_llist_node requestsNode;
};

static void dns_cb(int result, struct evutil_addrinfo *res, void *arg);
static void dns_cb_deferred(const np_error_code ec, void* userData);

static void async_resolve_v4(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);
static void async_resolve_v6(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

static struct np_dns_functions module = {
    &async_resolve_v4,
    &async_resolve_v6
};

struct np_dns nm_libevent_dns_get_impl(struct nm_libevent_dns* ctx)
{
    struct np_dns obj;
    obj.mptr = &module;
    obj.data = ctx;
    return obj;
}

np_error_code nm_libevent_dns_init(struct nm_libevent_dns* ctx, struct event_base* eventBase, struct nabto_device_mutex* coreMutex, struct np_event_queue* eq)
{
    ctx->stopped = false;
    ctx->mutex = coreMutex;
    ctx->cancelMutex = nabto_device_threads_create_mutex();
    if (ctx->cancelMutex == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->dnsBase = evdns_base_new(eventBase, 0);
    if (ctx->dnsBase == NULL) {
        nabto_device_threads_free_mutex(ctx->cancelMutex);
        return NABTO_EC_OUT_OF_MEMORY;
    }
    int r;
#if _WIN32
    r = evdns_base_config_windows_nameservers(ctx->dnsBase);
#else
    int opts = DNS_OPTION_NAMESERVERS | DNS_OPTION_HOSTSFILE;
    r = evdns_base_resolv_conf_parse(ctx->dnsBase, opts, "/etc/resolv.conf");
#endif
    if (r != 0) {
        NABTO_LOG_ERROR(LOG, "Could not configure name servers %d", r);
        nabto_device_threads_free_mutex(ctx->cancelMutex);
        evdns_base_free(ctx->dnsBase, 1);
        return NABTO_EC_UNKNOWN;
    }


    ctx->eventBase = eventBase;
    ctx->eq = *eq;
    nn_llist_init(&ctx->requests);
    return NABTO_EC_OK;
}

void nm_libevent_dns_stop(struct nm_libevent_dns* ctx)
{
    nabto_device_threads_mutex_lock(ctx->mutex);
    if (ctx->stopped) {
        nabto_device_threads_mutex_unlock(ctx->mutex);
        return;
    }
    ctx->stopped = true;

    nabto_device_threads_mutex_unlock(ctx->mutex);

    nabto_device_threads_mutex_lock(ctx->cancelMutex);
    struct nm_dns_request* request;
    NN_LLIST_FOREACH(request, &ctx->requests) {
        evdns_getaddrinfo_cancel(request->req);
    }
    nabto_device_threads_mutex_unlock(ctx->cancelMutex);
}

void nm_libevent_dns_deinit(struct nm_libevent_dns* ctx)
{
    nabto_device_threads_free_mutex(ctx->cancelMutex);
    evdns_base_free(ctx->dnsBase, 1);
}

static void async_resolve_v4(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct nm_libevent_dns* ctx = obj->data;
    struct evdns_base* dnsBase = ctx->dnsBase;

    if (ipsSize == 0) {
        np_completion_event_resolve(completionEvent, NABTO_EC_NO_DATA);
        return;
    }

    if (ctx->stopped) {
        np_completion_event_resolve(completionEvent, NABTO_EC_STOPPED);
        return;
    }

    {
        uint8_t dst[16];
        if (evutil_inet_pton(AF_INET6, host, dst) == 1) {
            // this is an ipv6 address do not try to resolve it as ipv4.
            np_completion_event_resolve(completionEvent, NABTO_EC_NO_DATA);
            return;
        }
    }

    {
        uint8_t dst[4];
        if (evutil_inet_pton(AF_INET, host, dst) == 1) {
            // this is an ipv4 address do not try to resolve it as ipv6.
            ips[0].type = NABTO_IPV4;
            memcpy(ips[0].ip.v4, dst, 4);
            *ipsResolved = 1;
            np_completion_event_resolve(completionEvent, NABTO_EC_OK);
            return;
        }
    }

    struct nm_dns_request* dnsRequest = np_calloc(1, sizeof(struct nm_dns_request));
    if (dnsRequest == NULL) {
        np_completion_event_resolve(completionEvent, NABTO_EC_OUT_OF_MEMORY);
        return;
    }
    np_error_code ec = np_completion_event_init(&ctx->eq, &dnsRequest->dnsCbDeZalgo, dns_cb_deferred, dnsRequest);
    if (ec != NABTO_EC_OK) {
        np_free(dnsRequest);
        np_completion_event_resolve(completionEvent, ec);
        return;
    }
    dnsRequest->completionEvent = completionEvent;
    dnsRequest->ips = ips;
    dnsRequest->ipsSize = ipsSize;
    dnsRequest->ipsResolved = ipsResolved;
    dnsRequest->moduleContext = ctx;
    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof(struct evutil_addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_flags = 0; //AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST;
    hints.ai_socktype = SOCK_DGRAM;
    const char* service = "443";
    nn_llist_append(&ctx->requests, &dnsRequest->requestsNode, dnsRequest);
    dnsRequest->req = evdns_getaddrinfo(dnsBase, host, service, &hints, dns_cb, dnsRequest);
}

static void async_resolve_v6(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct nm_libevent_dns* ctx = obj->data;
    struct evdns_base* dnsBase = ctx->dnsBase;

    if (ipsSize == 0) {
        np_completion_event_resolve(completionEvent, NABTO_EC_NO_DATA);
        return;
    }

    if (ctx->stopped) {
        np_completion_event_resolve(completionEvent, NABTO_EC_STOPPED);
        return;
    }

    {
        uint8_t dst[4];
        if (evutil_inet_pton(AF_INET, host, dst) == 1) {
            // this is an ipv4 address do not try to resolve it as ipv6.
            np_completion_event_resolve(completionEvent, NABTO_EC_NO_DATA);
            return;
        }
    }

    {
        uint8_t dst[16];
        if (evutil_inet_pton(AF_INET6, host, dst) == 1) {
            // this is an ipv6 address just resolve it as such.
            ips[0].type = NABTO_IPV6;
            memcpy(ips[0].ip.v6, dst, 16);
            *ipsResolved = 1;
            np_completion_event_resolve(completionEvent, NABTO_EC_OK);
            return;
        }
    }

    struct nm_dns_request* dnsRequest = np_calloc(1, sizeof(struct nm_dns_request));
    if (dnsRequest == NULL) {
        np_completion_event_resolve(completionEvent, NABTO_EC_OUT_OF_MEMORY);
        return;
    }
    np_error_code ec = np_completion_event_init(&ctx->eq, &dnsRequest->dnsCbDeZalgo, dns_cb_deferred, dnsRequest);
    if (ec != NABTO_EC_OK) {
        np_free(dnsRequest);
        np_completion_event_resolve(completionEvent, ec);
        return;
    }
    dnsRequest->completionEvent = completionEvent;
    dnsRequest->ips = ips;
    dnsRequest->ipsSize = ipsSize;
    dnsRequest->ipsResolved = ipsResolved;
    dnsRequest->moduleContext = ctx;
    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof(struct evutil_addrinfo));
    hints.ai_family = AF_INET6;
    hints.ai_flags = 0; //AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST;
    hints.ai_socktype = SOCK_DGRAM;
    const char* service = "443";
    nn_llist_append(&ctx->requests, &dnsRequest->requestsNode, dnsRequest);
    dnsRequest->req = evdns_getaddrinfo(dnsBase, host, service, &hints, dns_cb, dnsRequest);
}

void dns_cb(int result, struct evutil_addrinfo *res, void *arg)
{
    struct nm_dns_request* ctx = arg;

    nabto_device_threads_mutex_lock(ctx->moduleContext->cancelMutex);
    nn_llist_erase_node(&ctx->requestsNode);
    ctx->cbResult = result;
    ctx->cbRes = res;
    nabto_device_threads_mutex_unlock(ctx->moduleContext->cancelMutex);
    np_completion_event_resolve(&ctx->dnsCbDeZalgo, NABTO_EC_OK);
}

void dns_cb_deferred(const np_error_code cbec, void* userData)
{
    struct nm_dns_request* ctx = userData;
    struct nm_libevent_dns* moduleContext = ctx->moduleContext;
    np_error_code ec = NABTO_EC_OK;
    size_t resolved = 0;
    struct evutil_addrinfo* origRes = ctx->cbRes;
    struct evutil_addrinfo* res = ctx->cbRes;
    int result = ctx->cbResult;

    if (result == EVUTIL_EAI_FAIL) {
        // this error also comes if evdns_base_free has been called, in that case we should not use dnsBase anymore.
        // maybe the system has changed nameservers, reload them
        if (!moduleContext->stopped) {
            struct evdns_base* base = moduleContext->dnsBase;
#ifdef _WIN32
            evdns_base_clear_host_addresses(base);
            evdns_base_config_windows_nameservers(base);
#else
            evdns_base_clear_host_addresses(base);
            evdns_base_resolv_conf_parse(base, DNS_OPTION_NAMESERVERS, "/etc/resolv.conf");
#endif
        }
    }

    if (result != 0) {
        ec = NABTO_EC_UNKNOWN;
    } else {
        while (res != NULL && resolved < ctx->ipsSize) {
            if (res->ai_family == AF_INET) {
                ctx->ips[resolved].type = NABTO_IPV4;
                struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
                memcpy(ctx->ips[resolved].ip.v4,
                       (uint8_t*)(&addr->sin_addr.s_addr), 4);
                resolved++;
            } else if (res->ai_family == AF_INET6) {
                ctx->ips[resolved].type = NABTO_IPV6;
                struct sockaddr_in6* addr = (struct sockaddr_in6*)res->ai_addr;
                memcpy(ctx->ips[resolved].ip.v6, &addr->sin6_addr, 16);
                resolved++;
            }
            res = res->ai_next;
        }
        if (resolved == 0) {
            ec = NABTO_EC_NO_DATA;
        }
    }
    *ctx->ipsResolved = resolved;
    np_completion_event_resolve(ctx->completionEvent, ec);
    if (origRes != NULL) {
        evutil_freeaddrinfo(origRes);
    }
    np_completion_event_deinit(&ctx->dnsCbDeZalgo);
    np_free(ctx);
}
