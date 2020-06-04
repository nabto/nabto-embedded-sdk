
#include "nm_unix_dns.h"

#include <platform/np_logging.h>
#include <platform/np_error_code.h>
#include <platform/np_completion_event.h>

#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>

#include <nn/llist.h>

#define LOG NABTO_LOG_MODULE_DNS

/**
 * A resolver has a list of events. Each event is a hostname which is
 * either resolved to v4 or v6 addresses
 */
struct np_dns_resolver {
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    struct nn_llist events;
    bool stopped;
};

struct nm_dns_resolve_event {
    struct nn_llist_node eventsNode;
    struct np_ip_address* ips;
    size_t ipsSize;
    size_t* ipsResolved;
    const char* host;
    int family;
    struct np_completion_event* completionEvent;
};

static np_error_code create_resolver(void* data, struct np_dns_resolver** resolver);
static void destroy_resolver(struct np_dns_resolver* resolver);
static void stop_resolver(struct np_dns_resolver* resolver);
static void async_resolve_v4(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);
static void async_resolve_v6(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);
static void async_resolve(struct np_dns_resolver* resolver, int family, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

static struct np_dns_functions vtable = {
    .create_resolver = &create_resolver,
    .destroy_resolver = &destroy_resolver,
    .stop = &stop_resolver,
    .async_resolve_v4 = &async_resolve_v4,
    .async_resolve_v6 = &async_resolve_v6
};

struct np_dns nm_unix_dns_create()
{
    struct np_dns dns;
    dns.vptr = &vtable;
    dns.data = NULL;
    return dns;
}

np_error_code resolve_one_ec(struct nm_dns_resolve_event* event)
{
    struct np_ip_address* ips = event->ips;
    *event->ipsResolved = 0;
    struct addrinfo hints;
    struct addrinfo *infoptr;
    memset(&hints, 0, sizeof (struct addrinfo));

    hints.ai_socktype = SOCK_DGRAM;

    NABTO_LOG_TRACE(LOG, "Resolving host: %s", event->host);

    hints.ai_family = event->family;
    int res =  getaddrinfo(event->host, NULL, &hints, &infoptr);
    if (res != 0) {
        // Errors may be protocol specific, and not significant. If everything fails, the user will get an error
        if (res == EAI_SYSTEM) {
            NABTO_LOG_TRACE(LOG, "Failed to get address info for family %d: (%i) '%s'", event->family, errno, strerror(errno));
        } else {
            NABTO_LOG_TRACE(LOG, "Failed to get address info for family %d: (%i) '%s'", event->family, res, gai_strerror(res));
        }
        return NABTO_EC_NOT_FOUND;
    }
    struct addrinfo *p = infoptr;

    size_t resolved = 0;
    while (p != NULL) {
        if (*(event->ipsResolved) < event->ipsSize) {
            if (p->ai_family == AF_INET) {
                ips[resolved].type = NABTO_IPV4;
                struct sockaddr_in* addr = (struct sockaddr_in*)p->ai_addr;
                memcpy(ips[resolved].ip.v4, &addr->sin_addr, sizeof(addr->sin_addr));
                resolved++;
            } else if (p->ai_family == AF_INET6) {
                ips[resolved].type = NABTO_IPV6;
                struct sockaddr_in6* addr = (struct sockaddr_in6*)p->ai_addr;
                memcpy(ips[resolved].ip.v6, &addr->sin6_addr, sizeof(addr->sin6_addr));
                resolved++;
            }
        }
        p = p->ai_next;
    }

    *event->ipsResolved = resolved;

    freeaddrinfo(infoptr);
    return NABTO_EC_OK;
}

void resolve_one(struct nm_dns_resolve_event* event)
{
    np_error_code ec = resolve_one_ec(event);
    np_completion_event_resolve(event->completionEvent, ec);
    free(event);
}

void* resolve_thread(void* data)
{
    struct np_dns_resolver* resolver = data;
    while (true) {
        pthread_mutex_lock(&resolver->mutex);
        if (resolver->stopped) {
            pthread_mutex_unlock(&resolver->mutex);
            return NULL;
        }
        if (nn_llist_empty(&resolver->events)) {
            pthread_cond_wait(&resolver->condition, &resolver->mutex);
            pthread_mutex_unlock(&resolver->mutex);
        } else {
            struct nn_llist_iterator first = nn_llist_begin(&resolver->events);
            struct nm_dns_resolve_event* event = nn_llist_get_item(&first);
            nn_llist_erase(&first);
            pthread_mutex_unlock(&resolver->mutex);
            resolve_one(event);
        }
    }
}

np_error_code create_resolver(void* data, struct np_dns_resolver** resolver)
{
    struct np_dns_resolver* r = calloc(1, sizeof(struct np_dns_resolver));

    nn_llist_init(&r->events);

    pthread_mutex_init(&r->mutex, NULL);
    pthread_cond_init(&r->condition, NULL);
    pthread_create(&r->thread, NULL, &resolve_thread, r);
    *resolver = r;
    return NABTO_EC_OK;
}

void destroy_resolver(struct np_dns_resolver* resolver)
{
    stop_resolver(resolver);
    pthread_mutex_destroy(&resolver->mutex);
    nn_llist_deinit(&resolver->events);
    free(resolver);
}

void stop_resolver(struct np_dns_resolver* resolver)
{
    if (resolver->stopped) {
        return;
    }
    pthread_mutex_lock(&resolver->mutex);
    resolver->stopped = true;

    while (!nn_llist_empty(&resolver->events)) {
        struct nn_llist_iterator first = nn_llist_begin(&resolver->events);
        nn_llist_erase(&first);
        struct nm_dns_resolve_event* event = nn_llist_get_item(&first);
        np_completion_event_resolve(event->completionEvent, NABTO_EC_STOPPED);
        free(event);
    }

    pthread_mutex_unlock(&resolver->mutex);
    pthread_cond_signal(&resolver->condition);
    pthread_join(resolver->thread, NULL);
}

void async_resolve_v4(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    async_resolve(resolver, AF_INET, host, ips, ipsSize, ipsResolved, completionEvent);
}

void async_resolve_v6(struct np_dns_resolver* resolver, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    async_resolve(resolver, AF_INET6, host, ips, ipsSize, ipsResolved, completionEvent);
}

void async_resolve(struct np_dns_resolver* resolver, int family, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    if (resolver->stopped) {
        np_completion_event_resolve(completionEvent, NABTO_EC_STOPPED);
        return;
    }
    struct nm_dns_resolve_event* r = calloc(1,sizeof(struct nm_dns_resolve_event));
    r->host = host;
    r->ips = ips;
    r->ipsSize = ipsSize;
    r->ipsResolved = ipsResolved;
    r->completionEvent = completionEvent;
    r->family = family;

    pthread_mutex_lock(&resolver->mutex);
    nn_llist_append(&resolver->events, &r->eventsNode, r);
    pthread_mutex_unlock(&resolver->mutex);
    pthread_cond_signal(&resolver->condition);
}
