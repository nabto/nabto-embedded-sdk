
#include "nm_unix_dns.h"

#include <platform/np_logging.h>
#include <platform/np_error_code.h>

#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_DNS

struct nm_unix_dns_ctx {
    struct np_timed_event ev;
    const char* host;
    np_dns_resolve_callback cb;
    np_error_code ec;
    void* data;
    bool resolver_is_running;
    struct np_platform* pl;

    struct np_ip_address v4Ips[NP_DNS_RESOLVED_IPS_MAX];
    size_t v4IpsSize;
    struct np_ip_address v6Ips[NP_DNS_RESOLVED_IPS_MAX];
    size_t v6IpsSize;
};

void nm_unix_dns_check_resolved(const np_error_code ec, void* data);


bool resolve_dns(const char* host, int family, struct np_ip_address* list, size_t* size)
{
    struct np_ip_address* ips = list;
    struct addrinfo hints;
    struct addrinfo *infoptr;
    memset(&hints, 0, sizeof (struct addrinfo));

    hints.ai_socktype = SOCK_DGRAM;

    NABTO_LOG_TRACE(LOG, "Resolving host: %s", host);

    hints.ai_family = family;
    int res =  getaddrinfo(host, NULL, &hints, &infoptr);
    if (res != 0) {
        if (res == EAI_SYSTEM) {
            NABTO_LOG_ERROR(LOG, "Failed to get address info: (%i) '%s'", errno, strerror(errno));
        } else {
            NABTO_LOG_ERROR(LOG, "Failed to get address info: (%i) '%s'", res, gai_strerror(res));
        }
        return false;
    }
    struct addrinfo *p = infoptr;
    int i = 0;
    *size = 0;
    for (i = 0; i < NP_DNS_RESOLVED_IPS_MAX; i++) {
        if (p == NULL) {
            break;
        }
        NABTO_LOG_TRACE(LOG, "Found IPv4 address");

        if (family == AF_INET && p->ai_family == AF_INET) {
            ips[i].type = NABTO_IPV4;
            struct sockaddr_in* addr = (struct sockaddr_in*)p->ai_addr;
            memcpy(ips[i].ip.v4, &addr->sin_addr, sizeof(addr->sin_addr));//p->ai_addrlen);
        } else if (family == AF_INET6 && p->ai_family == AF_INET6) {
            ips[i].type = NABTO_IPV6;
            struct sockaddr_in6* addr = (struct sockaddr_in6*)p->ai_addr;
            memcpy(ips[i].ip.v6, &addr->sin6_addr, sizeof(addr->sin6_addr));//p->ai_addrlen);
        } else {
            NABTO_LOG_ERROR(LOG, "Resolved hostname was neither IPv4 or IPv6");
            *size -= 1; // negate the ++ below
            i--; // dont advance array index if it was not used
        }
        *size += 1;
        p = p->ai_next;
    }
    freeaddrinfo(infoptr);
    return true;
}

void* resolver_thread(void* ctx)
{
    struct nm_unix_dns_ctx* state = (struct nm_unix_dns_ctx*)ctx;
    if (!resolve_dns(state->host, AF_INET, state->v4Ips, &state->v4IpsSize)) {
        // FAIL
        state->ec = NABTO_EC_UNKNOWN;
        state->resolver_is_running = false;
        return NULL;
    }
    if (!resolve_dns(state->host, AF_INET6, state->v6Ips, &state->v6IpsSize)) {
        // FAIL
        state->ec = NABTO_EC_UNKNOWN;
        state->resolver_is_running = false;
        return NULL;
    }
    state->resolver_is_running = false;
    return NULL;
}

void nm_unix_dns_init(struct np_platform* pl)
{
    pl->dns.async_resolve = &nm_unix_dns_resolve;
}

np_error_code nm_unix_dns_resolve(struct np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data)
{
    pthread_t thread;
    pthread_attr_t attr;
    struct nm_unix_dns_ctx* ctx;
    if (pthread_attr_init(&attr) !=0) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize pthread_attr");
        return NABTO_EC_UNKNOWN;
    }
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
        NABTO_LOG_ERROR(LOG, "Failed to set detach state for pthread_attr");
        pthread_attr_destroy(&attr);
        return NABTO_EC_UNKNOWN;
    }
    ctx = (struct nm_unix_dns_ctx*)malloc(sizeof(struct nm_unix_dns_ctx));
    if (!ctx) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate DNS context");
        return NABTO_EC_UNKNOWN;
    }
    ctx->data = data;
    ctx->host = host;
    ctx->cb = cb;
    ctx->pl = pl;
    ctx->ec = NABTO_EC_OK;
    ctx->resolver_is_running = true;

    if (pthread_create(&thread, &attr, resolver_thread, ctx) != 0) {
        NABTO_LOG_ERROR(LOG, "Failed to create pthread");
        pthread_attr_destroy(&attr);
        return NABTO_EC_UNKNOWN;
    }
    pthread_attr_destroy(&attr);
    np_event_queue_post_timed_event(pl, &ctx->ev, 50, &nm_unix_dns_check_resolved, ctx);
    return NABTO_EC_OK;
}

void nm_unix_dns_check_resolved(const np_error_code ec, void* data)
{
    struct nm_unix_dns_ctx* ctx = (struct nm_unix_dns_ctx*)data;
    if(ctx->resolver_is_running) {
        np_event_queue_post_timed_event(ctx->pl, &ctx->ev, 50, &nm_unix_dns_check_resolved, data);
        return;
    } else {
        ctx->cb(ctx->ec, ctx->v4Ips, ctx->v4IpsSize, ctx->v6Ips, ctx->v6IpsSize, ctx->data);
        free(ctx);
    }
}
