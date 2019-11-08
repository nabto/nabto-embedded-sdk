#include "nm_win_dns.h"

#include <platform/np_logging.h>
#include <platform/np_error_code.h>
#include <platform/np_platform.h>

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <string.h>

#define LOG NABTO_LOG_MODULE_DNS

struct nm_win_dns_ctx {
    struct np_timed_event ev;
    const char* host;
    size_t recSize;
    np_dns_resolve_callback cb;
    np_error_code ec;
    void* data;
    bool resolverIsRunning;
    struct np_platform* pl;
    struct np_ip_address ips[NP_DNS_RESOLVED_IPS_MAX];
};

void nm_win_dns_check_resolved(const np_error_code ec, void* data);

DWORD WINAPI resolver_thread(LPVOID data) {
    struct nm_win_dns_ctx* ctx = (struct nm_win_dns_ctx*)data;
    NABTO_LOG_TRACE(LOG, "thread start for host: %s", ctx->host);
    struct addrinfo hints, *infoptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    int res = getaddrinfo(ctx->host, "80" , &hints, &infoptr); //  GetAddrInfoW
    ctx->ec = NABTO_EC_UNKNOWN; // in case we dont find suitable addresses
    if (res) {
        NABTO_LOG_ERROR(LOG, "getaddrinfo: %s\n", gai_strerror(res));
    } else {
        struct addrinfo* p;
        ctx->recSize = 0;
        for (p = infoptr; p != NULL; p = p->ai_next) {
            if (p->ai_family == AF_INET) {
                struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in *) p->ai_addr;
                NABTO_LOG_TRACE(LOG, "Found IPv4");
                ctx->ec = NABTO_EC_OK;
                ctx->ips[ctx->recSize].type = NABTO_IPV4;
                memcpy(ctx->ips[ctx->recSize].v4.addr, &sockaddr_ipv4->sin_addr, 4);
                ctx->recSize++;
            } else if (p->ai_family == AF_INET6) {
                struct sockaddr_in6* sockaddr_ipv6 = (struct sockaddr_in6 *) p->ai_addr;
                NABTO_LOG_TRACE(LOG, "Found IPv6");
                ctx->ec = NABTO_EC_OK;
                ctx->ips[ctx->recSize].type = NABTO_IPV6;
                memcpy(ctx->ips[ctx->recSize].v6.addr, &sockaddr_ipv6->sin6_addr, 16);
                ctx->recSize++;
            } else {
                // unknown address family, skipping
            }
            if (ctx->recSize == NP_DNS_RESOLVED_IPS_MAX) {
                break;
            }
        }
        freeaddrinfo(infoptr);
    }
    NABTO_LOG_ERROR(LOG, "Resolver thread returning");
    ctx->resolverIsRunning = false;
    return 0;
}

void nm_win_dns_init(struct np_platform* pl)
{
    pl->dns.async_resolve = &nm_win_dns_resolve;
}

np_error_code nm_win_dns_resolve(struct  np_platform* pl, const char* host, np_dns_resolve_callback cb, void* data) {
    NABTO_LOG_TRACE(LOG, "resolving %s", host);
    struct nm_win_dns_ctx* ctx = (struct nm_win_dns_ctx*)malloc(sizeof(struct nm_win_dns_ctx));
    if (!ctx) {
        NABTO_LOG_ERROR(LOG, "Failed to allocate context");
        return NABTO_EC_UNKNOWN;
    }
    memset(ctx, 0, sizeof(struct nm_win_dns_ctx));
    ctx->resolverIsRunning = true;
    ctx->data = data;
    ctx->host = host;
    ctx->cb = cb;
    ctx->pl = pl;
    ctx->ec = NABTO_EC_OPERATION_IN_PROGRESS;
    HANDLE thread;
    NABTO_LOG_TRACE(LOG, "creating thread");
    thread = CreateThread(NULL, 0, resolver_thread, ctx, 0, NULL);
    if (!thread) {
        NABTO_LOG_ERROR(LOG, "Failed to create resolver thread");
        free(ctx);
        return NABTO_EC_UNKNOWN;
    }
    np_event_queue_post_timed_event(ctx->pl, &ctx->ev, 50, &nm_win_dns_check_resolved, ctx);
    return NABTO_EC_OK;
}

void nm_win_dns_check_resolved(const np_error_code ec, void* data) {
    struct nm_win_dns_ctx* ctx = (struct nm_win_dns_ctx*)data;
    if (ctx->resolverIsRunning) {
        NABTO_LOG_TRACE(LOG, "dns is NOT resolved");
        np_event_queue_post_timed_event(ctx->pl, &ctx->ev, 50, &nm_win_dns_check_resolved, data);
        return;
    } else {
        NABTO_LOG_TRACE(LOG, "dns is resolved");
        // TODO: resolve ipv6
        ctx->cb(ctx->ec, ctx->ips, ctx->recSize, NULL, 0, ctx->data);
        free(ctx);
        return;
    }
}
