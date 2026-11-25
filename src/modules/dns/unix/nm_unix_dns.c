
#include "nm_unix_dns.h"

#include <platform/np_allocator.h>
#include <platform/np_completion_event.h>
#include <platform/np_error_code.h>
#include <platform/np_logging.h>

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>


#include <nn/llist.h>
#include <nn/string.h>

#define LOG NABTO_LOG_MODULE_DNS

/**
 * A resolver has a list of events. Each event is a hostname which is
 * either resolved to v4 or v6 addresses
 */

struct nm_dns_resolve_event {
    struct nn_llist_node eventsNode;
    struct np_ip_address* ips;
    size_t ipsSize;
    size_t* ipsResolved;
    // The resolver's own copy, the caller's host can be freed once the
    // request is resolved.
    char* host;
    int family;
    // NULL if the request has been resolved with NABTO_EC_STOPPED.
    struct np_completion_event* completionEvent;
};

static void free_event(struct nm_dns_resolve_event* event);
static void async_resolve_v4(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);
static void async_resolve_v6(struct np_dns*obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);
static void async_resolve(struct nm_unix_dns_resolver* resolver, int family, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent);

static struct np_dns_functions module = {
    .async_resolve_v4 = &async_resolve_v4,
    .async_resolve_v6 = &async_resolve_v6
};

struct np_dns nm_unix_dns_resolver_get_impl(struct nm_unix_dns_resolver* resolver)
{
    struct np_dns dns;
    dns.mptr = &module;
    dns.data = resolver;
    return dns;
}

/**
 * Resolve into ips, which is owned by the resolver thread. The caller's ips
 * array is only written if the request is still outstanding.
 */
np_error_code resolve_one_ec(struct nm_dns_resolve_event* event, struct np_ip_address* ips, size_t* ipsResolved)
{
    *ipsResolved = 0;
    struct addrinfo hints;
    struct addrinfo *infoptr = NULL;
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
        if (resolved < event->ipsSize) {
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

    *ipsResolved = resolved;

    freeaddrinfo(infoptr);
    return NABTO_EC_OK;
}

void resolve_one(struct nm_unix_dns_resolver* resolver, struct nm_dns_resolve_event* event)
{
    size_t resolved = 0;
    np_error_code ec = NABTO_EC_OUT_OF_MEMORY;
    struct np_ip_address* ips = NULL;
    if (event->ipsSize > 0) {
        ips = np_calloc(event->ipsSize, sizeof(struct np_ip_address));
    }
    if (ips != NULL || event->ipsSize == 0) {
        ec = resolve_one_ec(event, ips, &resolved);
    }

    pthread_mutex_lock(&resolver->mutex);
    resolver->current = NULL;
    if (event->completionEvent != NULL) {
        if (ec == NABTO_EC_OK && ips != NULL && resolved > 0) {
            memcpy(event->ips, ips, resolved * sizeof(struct np_ip_address));
        }
        *event->ipsResolved = resolved;
        np_completion_event_resolve(event->completionEvent, ec);
    }
    pthread_mutex_unlock(&resolver->mutex);
    np_free(ips);
    free_event(event);
}

void free_event(struct nm_dns_resolve_event* event)
{
    np_free(event->host);
    np_free(event);
}

void* resolve_thread(void* data)
{
    struct nm_unix_dns_resolver* resolver = data;
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
            resolver->current = event;
            pthread_mutex_unlock(&resolver->mutex);
            resolve_one(resolver, event);
        }
    }
}

np_error_code nm_unix_dns_resolver_init(struct nm_unix_dns_resolver* r)
{
    nn_llist_init(&r->events);

    r->stopped = false;
    r->thread = 0;
    r->current = NULL;

    pthread_mutex_init(&r->mutex, NULL);
    pthread_cond_init(&r->condition, NULL);
    return NABTO_EC_OK;
}

void nm_unix_dns_resolver_deinit(struct nm_unix_dns_resolver* resolver)
{
    nm_unix_dns_resolver_stop(resolver);
    if (resolver->thread != 0) {
        // Waits for a getaddrinfo call in progress, its result is dropped.
        pthread_join(resolver->thread, NULL);
        resolver->thread = 0;
    }
    pthread_mutex_destroy(&resolver->mutex);
    nn_llist_deinit(&resolver->events);
}

void nm_unix_dns_resolver_run(struct nm_unix_dns_resolver* r)
{
    pthread_create(&r->thread, NULL, &resolve_thread, r);
}

void nm_unix_dns_resolver_stop(struct nm_unix_dns_resolver* resolver)
{
    pthread_mutex_lock(&resolver->mutex);
    if (resolver->stopped) {
        pthread_mutex_unlock(&resolver->mutex);
        return;
    }
    resolver->stopped = true;

    while (!nn_llist_empty(&resolver->events)) {
        struct nn_llist_iterator first = nn_llist_begin(&resolver->events);
        struct nm_dns_resolve_event* event = nn_llist_get_item(&first);
        nn_llist_erase(&first);
        np_completion_event_resolve(event->completionEvent, NABTO_EC_STOPPED);
        free_event(event);
    }
    if (resolver->current != NULL && resolver->current->completionEvent != NULL) {
        // getaddrinfo cannot be cancelled, the resolver thread drops the
        // result.
        np_completion_event_resolve(resolver->current->completionEvent, NABTO_EC_STOPPED);
        resolver->current->completionEvent = NULL;
    }

    pthread_mutex_unlock(&resolver->mutex);
    pthread_cond_signal(&resolver->condition);
}

void async_resolve_v4(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct nm_unix_dns_resolver* resolver = obj->data;
    async_resolve(resolver, AF_INET, host, ips, ipsSize, ipsResolved, completionEvent);
}

void async_resolve_v6(struct np_dns* obj, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct nm_unix_dns_resolver* resolver = obj->data;
    async_resolve(resolver, AF_INET6, host, ips, ipsSize, ipsResolved, completionEvent);
}

void async_resolve(struct nm_unix_dns_resolver* resolver, int family, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    pthread_mutex_lock(&resolver->mutex);
    bool stopped = resolver->stopped;
    pthread_mutex_unlock(&resolver->mutex);
    if (stopped) {
        np_completion_event_resolve(completionEvent, NABTO_EC_STOPPED);
        return;
    }
    struct nm_dns_resolve_event* r = np_calloc(1,sizeof(struct nm_dns_resolve_event));
    if (r == NULL) {
        np_completion_event_resolve(completionEvent, NABTO_EC_OUT_OF_MEMORY);
        return;
    }
    r->host = nn_strdup(host, np_allocator_get());
    if (r->host == NULL) {
        np_free(r);
        np_completion_event_resolve(completionEvent, NABTO_EC_OUT_OF_MEMORY);
        return;
    }
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
