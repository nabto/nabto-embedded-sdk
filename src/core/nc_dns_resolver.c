#include "nc_dns_resolver.h"

#include <platform/np_dns.h>
#include <platform/np_platform.h>

static void dns_resolved_callback_v4(const np_error_code ec, void* data);
static void dns_resolved_callback_v6(const np_error_code ec, void* data);
static void dns_resolved(struct nc_dns_resolver_context* ctx);

np_error_code nc_dns_resolver_init(struct np_platform* pl, struct nc_dns_resolver_context* ctx, struct np_dns_resolver* resolver)
{
    ctx->resolver = resolver;
    ctx->pl = pl;
    np_completion_event_init(pl, &ctx->v4CompletionEvent, &dns_resolved_callback_v4, ctx);
    np_completion_event_init(pl, &ctx->v6CompletionEvent, &dns_resolved_callback_v6, ctx);
    return NABTO_EC_OK;
}

void nc_dns_resolver_deinit(struct nc_dns_resolver_context* ctx)
{
    np_completion_event_deinit(&ctx->v4CompletionEvent);
    np_completion_event_deinit(&ctx->v6CompletionEvent);
}

void nc_dns_resolver_resolve(struct nc_dns_resolver_context* ctx, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
{
    struct np_platform* pl = ctx->pl;
    ctx->resolvedCompletionEvent = completionEvent;
    ctx->ips = ips;
    ctx->ipsSize = ipsSize;
    ctx->ipsResolved = ipsResolved;
    ctx->v4IpsSize = 0;
    ctx->v6IpsSize = 0;
    ctx->v4Ec = NABTO_EC_OPERATION_IN_PROGRESS;
    ctx->v6Ec = NABTO_EC_OPERATION_IN_PROGRESS;
    pl->dns.async_resolve_v4(ctx->resolver, host, ctx->v4Ips, NC_DNS_RESOLVER_MAX_IPS, &ctx->v4IpsSize, &ctx->v4CompletionEvent);
    pl->dns.async_resolve_v6(ctx->resolver, host, ctx->v6Ips, NC_DNS_RESOLVER_MAX_IPS, &ctx->v6IpsSize, &ctx->v6CompletionEvent);
}

void dns_resolved_callback_v4(const np_error_code ec, void* data)
{
    struct nc_dns_resolver_context* ctx = data;
    ctx->v4Ec = ec;
    dns_resolved(ctx);
}

void dns_resolved_callback_v6(const np_error_code ec, void* data)
{
    struct nc_dns_resolver_context* ctx = data;
    ctx->v6Ec = ec;
    dns_resolved(ctx);
}

void dns_resolved(struct nc_dns_resolver_context* ctx)
{
    if (ctx->v4Ec == NABTO_EC_OPERATION_IN_PROGRESS ||
        ctx->v6Ec == NABTO_EC_OPERATION_IN_PROGRESS)
    {
        // wait for both ipv6 and ipv4 to be resolved
        return;
    }

    if (ctx->v4Ec != NABTO_EC_OK && ctx->v6Ec != NABTO_EC_OK) {
        // just resolve with one of the errors.
        np_completion_event_resolve(ctx->resolvedCompletionEvent, ctx->v4Ec);
        return;
    }

    size_t v4IpsSize = ctx->v4IpsSize;
    size_t v6IpsSize = ctx->v6IpsSize;
    size_t ipsResolved = 0;
    for (size_t i = 0; i < v4IpsSize+v6IpsSize; i++) {
        if (ipsResolved < ctx->ipsSize) {
            if (i < v4IpsSize) {
                ctx->ips[ipsResolved] = ctx->v4Ips[i];
                ipsResolved++;
            }
        }
        if (ipsResolved < ctx->ipsSize) {
            if (i < v6IpsSize) {
                ctx->ips[ipsResolved] = ctx->v6Ips[i];
                ipsResolved++;
            }
        }
    }
    *ctx->ipsResolved = ipsResolved;
    if (ipsResolved == 0) {
        np_completion_event_resolve(ctx->resolvedCompletionEvent, NABTO_EC_NOT_FOUND);
    } else {
        np_completion_event_resolve(ctx->resolvedCompletionEvent, NABTO_EC_OK);
    }
}
