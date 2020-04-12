#include "nm_libevent_dns.h"
#include <event2/dns.h>

#include <platform/np_ip_address.h>
#include <platform/np_dns.h>
#include <platform/np_platform.h>

#include <stdlib.h>
#include <string.h>

#define DNS_RECORDS_SIZE 4

struct dns_request {
    struct np_platform* pl;
    struct evdns_request* request;
    np_dns_resolve_callback callback;
    void* callbackUserData;

    struct np_ip_address v4Records[DNS_RECORDS_SIZE];
    struct np_ip_address v6Records[DNS_RECORDS_SIZE];
    size_t v4RecordsSize;
    size_t v6RecordsSize;
    const char* host;

    struct np_event callbackEvent;
};

static np_error_code async_resolve(struct np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data);
static void dns_cbv4(int result, char type, int count, int ttl, void *addresses, void *arg);
static void dns_cbv6(int result, char type, int count, int ttl, void* addresses, void* arg);
static void dns_done_event(void* data);

void nm_libevent_dns_init(struct np_platform* pl, struct event_base *event_base)
{

    struct evdns_base * base = evdns_base_new(event_base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
    pl->dnsData = base;
    pl->dns.async_resolve = &async_resolve;
}

void nm_libevent_dns_deinit(struct np_platform* pl)
{
    evdns_base_free(pl->dnsData, 1);
    pl->dnsData = NULL;
}


np_error_code async_resolve(struct np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data)
{
    struct evdns_base* base = pl->dnsData;
    int flags = 0;
    struct dns_request* req = calloc(1, sizeof(struct dns_request));
    req->pl = pl;
    req->callback = cb;
    req->callbackUserData = data;
    req->host = host;
    req->request = evdns_base_resolve_ipv4(base, host, flags, dns_cbv4, req);
    // TODO check for NULL
    return NABTO_EC_OK;
}

void dns_cbv4(int result, char type, int count, int ttl, void *addresses, void *arg)
{
    struct dns_request* req = arg;

    struct np_platform* pl = req->pl;
    struct evdns_base* base = pl->dnsData;

    if (result == DNS_ERR_NONE && type == DNS_IPv4_A) {
        int i;
        for (i = 0; i < count && i < DNS_RECORDS_SIZE; i++) {
            req->v4Records[i].type = NABTO_IPV4;
            uint8_t* addressStart = ((uint8_t*)addresses) + i*4;
            memcpy(req->v4Records[i].ip.v4, addressStart, 4);
        }
        req->v4RecordsSize = i;
    }
    int flags = 0;
    evdns_base_resolve_ipv6(base, req->host, flags, dns_cbv6, req);
    // TODO check for NULL
}

void dns_cbv6(int result, char type, int count, int ttl, void* addresses, void* arg)
{
    struct dns_request* req = arg;

    if (result == DNS_ERR_NONE && type == DNS_IPv6_AAAA) {
        int i;
        for (i = 0; i < count && i < DNS_RECORDS_SIZE; i++) {
            req->v6Records[i].type = NABTO_IPV6;
            uint8_t* addressStart = ((uint8_t*)addresses) + i*16;
            memcpy(req->v6Records[i].ip.v6, addressStart, 16);
        }
        req->v6RecordsSize = i;
    }

    // post to event queue such that the callback is completed on the right queue.
    struct np_platform* pl = req->pl;
    np_event_queue_post(pl, &req->callbackEvent, &dns_done_event, req);
}

void dns_done_event(void* data)
{
    struct dns_request* req = data;
    req->callback(NABTO_EC_OK, req->v4Records, req->v4RecordsSize, req->v6Records, req->v6RecordsSize, req->callbackUserData);
    free(req);
}
