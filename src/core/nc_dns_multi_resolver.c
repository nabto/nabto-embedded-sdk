#include "nc_dns_multi_resolver.h"

#include <platform/np_dns_wrapper.h>
#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <platform/np_allocator.h>
#include <nn/string.h>

#define LOG NABTO_LOG_MODULE_DNS


static void dns_resolved_callback_v4(const np_error_code ec, void* data);
static void dns_resolved_callback_v6(const np_error_code ec, void* data);
static void dns_resolved(struct nc_dns_multi_resolver_context* ctx);
void print_dns_results(struct nc_dns_multi_resolver_context* ctx, np_error_code ec);

np_error_code nc_dns_multi_resolver_init(struct np_platform* pl, struct nc_dns_multi_resolver_context* ctx)
{
    ctx->pl = pl;
    np_error_code ec;
    struct np_event_queue* eq = &pl->eq;
    ec = np_completion_event_init(eq, &ctx->v4CompletionEvent, &dns_resolved_callback_v4, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_completion_event_init(eq, &ctx->v6CompletionEvent, &dns_resolved_callback_v6, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    return NABTO_EC_OK;
}

void nc_dns_multi_resolver_deinit(struct nc_dns_multi_resolver_context* ctx)
{
    np_completion_event_deinit(&ctx->v4CompletionEvent);
    np_completion_event_deinit(&ctx->v6CompletionEvent);
}

void nc_dns_multi_resolver_resolve(struct nc_dns_multi_resolver_context* ctx, const char* host, struct np_ip_address* ips, size_t ipsSize, size_t* ipsResolved, struct np_completion_event* completionEvent)
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
    ctx->host = nn_strdup(host, np_allocator_get());
    np_dns_async_resolve_v4(&pl->dns, host, ctx->v4Ips, NC_DNS_MULTI_RESOLVER_MAX_IPS, &ctx->v4IpsSize, &ctx->v4CompletionEvent);
    np_dns_async_resolve_v6(&pl->dns, host, ctx->v6Ips, NC_DNS_MULTI_RESOLVER_MAX_IPS, &ctx->v6IpsSize, &ctx->v6CompletionEvent);
}

void dns_resolved_callback_v4(const np_error_code ec, void* data)
{
    struct nc_dns_multi_resolver_context* ctx = data;
    ctx->v4Ec = ec;
    dns_resolved(ctx);
}

void dns_resolved_callback_v6(const np_error_code ec, void* data)
{
    struct nc_dns_multi_resolver_context* ctx = data;
    ctx->v6Ec = ec;
    dns_resolved(ctx);
}

np_error_code dns_resolved_ec(struct nc_dns_multi_resolver_context* ctx)
{
    if (ctx->v4Ec != NABTO_EC_OK && ctx->v6Ec != NABTO_EC_OK) {
        // just resolve with one of the errors.
        return ctx->v4Ec;
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
    return NABTO_EC_OK;
}

void dns_resolved(struct nc_dns_multi_resolver_context* ctx)
{
    if (ctx->v4Ec == NABTO_EC_OPERATION_IN_PROGRESS ||
        ctx->v6Ec == NABTO_EC_OPERATION_IN_PROGRESS)
    {
        // wait for both ipv6 and ipv4 to be resolved
        return;
    }
    np_error_code ec = dns_resolved_ec(ctx);
    print_dns_results(ctx, ec);
    np_free(ctx->host);
    np_completion_event_resolve(ctx->resolvedCompletionEvent, ec);
}

void print_dns_results(struct nc_dns_multi_resolver_context* ctx, np_error_code ec)
{
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_INFO(LOG, "Failed to resolve hostname: %s with error: %s", ctx->host, np_error_code_to_string(ec));
    } else {
        NABTO_LOG_INFO(LOG, "Hostname: %s resolved to %d IPs", ctx->host, *ctx->ipsResolved);
        for (size_t i = 0; i < *ctx->ipsResolved; i++) {
            NABTO_LOG_INFO(LOG, "  resolved IP #%d: %s", i+1, np_ip_address_to_string(&ctx->ips[i]));
        }
    }
}
