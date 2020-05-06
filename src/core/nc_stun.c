#include "nc_stun.h"

#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_STUN

#ifndef NABTO_STUN_BUFFER_SIZE
#define NABTO_STUN_BUFFER_SIZE 512
#endif

// util functions
void nc_stun_resolve_callbacks(void* data);
size_t nc_stun_convert_ep_list(struct np_ip_address* ips, size_t ipsSize,
                               struct nabto_stun_endpoint* eps, size_t epsSize,
                               uint16_t port);
void nc_stun_event(struct nc_stun_context* ctx);

// Async callback functions
void nc_stun_analysed_cb(const np_error_code ec, const struct nabto_stun_result* res, void* data);
void nc_stun_send_to_cb(const np_error_code ec, void* data);
void nc_stun_handle_timeout(const np_error_code ec, void* data);
static void nc_stun_dns_cb(const np_error_code ec, void* data);

// stun module functions
uint32_t nc_stun_get_stamp(void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    return ctx->pl->ts.now_ms();
}
void nc_stun_log(const char* file, int line, enum nabto_stun_log_level level,
                 const char* fmt, va_list args, void* data)
{
    if (level == NABTO_STUN_LOG_LEVEL_INFO) {
        np_log.log(NABTO_LOG_SEVERITY_INFO, LOG, line, file, fmt, args);
    } else if (level == NABTO_STUN_LOG_LEVEL_TRACE) {
        np_log.log(NABTO_LOG_SEVERITY_TRACE, LOG, line, file, fmt, args);

    } else if (level == NABTO_STUN_LOG_LEVEL_DEBUG) {
        np_log.log(NABTO_LOG_SEVERITY_TRACE, LOG, line, file, fmt, args);

    } else if (level == NABTO_STUN_LOG_LEVEL_ERROR) {
        np_log.log(NABTO_LOG_SEVERITY_ERROR, LOG, line, file, fmt, args);

    }
}

bool nc_stun_get_rand(uint8_t* buf, uint16_t size, void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    struct np_platform* pl = ctx->pl;
    np_error_code ec = pl->random.random(pl, buf, size);
    if (ec == NABTO_EC_OK) {
        return true;
    } else {
        return false;
    }
}

// init function
np_error_code nc_stun_init(struct nc_stun_context* ctx,
                           struct np_dns_resolver* resolver,
                           struct np_platform* pl)
{
    memset(ctx, 0, sizeof(struct nc_stun_context));
    ctx->sendBuf = pl->buf.allocate();
    if (!ctx->sendBuf) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    ctx->pl = pl;
    ctx->state = NC_STUN_STATE_NONE;
    ctx->stunModule.get_stamp = &nc_stun_get_stamp;
    ctx->stunModule.log = &nc_stun_log;
    ctx->stunModule.get_rand = &nc_stun_get_rand;
    np_event_queue_create_timed_event(pl, &nc_stun_handle_timeout, ctx, &ctx->toEv);
    nc_dns_resolver_init(pl, &ctx->dnsResolver, resolver);
    np_completion_event_init(pl, &ctx->dnsCompletionEvent, &nc_stun_dns_cb, ctx);
    return NABTO_EC_OK;
}

void nc_stun_deinit(struct nc_stun_context* ctx)
{
    if (ctx->pl != NULL) { // if init called
        ctx->state = NC_STUN_STATE_ABORTED;
        struct np_platform* pl = ctx->pl;
        np_event_queue_cancel_timed_event(ctx->pl, ctx->toEv);
        pl->buf.free(ctx->sendBuf);

        np_event_queue_destroy_timed_event(pl, ctx->toEv);
        np_completion_event_deinit(&ctx->dnsCompletionEvent);
    }
}

void nc_stun_set_sockets(struct nc_stun_context* ctx, struct nc_udp_dispatch_context* udp, struct nc_udp_dispatch_context* secondaryUdp)
{
    ctx->priUdp = udp;
    ctx->secUdp = secondaryUdp;
}
void nc_stun_set_host(struct nc_stun_context* ctx, const char* hostname, uint16_t port)
{
    ctx->hostname = hostname;
    ctx->priPort = port;
}

void nc_stun_remove_sockets(struct nc_stun_context* ctx)
{
    ctx->priUdp = NULL;
    ctx->secUdp = NULL;
}

// analyze function
np_error_code nc_stun_async_analyze(struct nc_stun_context* ctx, bool simple,
                                    nc_stun_analyze_callback cb, void* data)
{
    int i;
    bool found = false;
    if (ctx->state == NC_STUN_STATE_ABORTED) {
        return NABTO_EC_ABORTED;
    }
    NABTO_LOG_TRACE(LOG, "Starting STUN analysis for host: %s", ctx->hostname);
    if (ctx->hostname == NULL) {
        NABTO_LOG_ERROR(LOG, "Stun analysis started before host was configured");
        return NABTO_EC_INVALID_STATE;
    }
    for (i = 0; i < NC_STUN_MAX_CALLBACKS; i++) {
        if (ctx->cbs[i].cb == NULL) {
            ctx->cbs[i].cb = cb;
            ctx->cbs[i].data = data;
            found  = true;
            break;
        }
    }
    if (!found) {
        NABTO_LOG_ERROR(LOG, "Out of callbacks");
        return NABTO_EC_UNKNOWN;
    }
    if (ctx->state == NC_STUN_STATE_RUNNING) {
        NABTO_LOG_INFO(LOG, "Stun already running, adding callback");
        return NABTO_EC_OK;
    }

    ctx->simple = simple;
    ctx->state = NC_STUN_STATE_RUNNING;
    nc_dns_resolver_resolve(&ctx->dnsResolver, ctx->hostname, ctx->resolvedIps, NC_STUN_MAX_ENDPOINTS, &ctx->resolvedIpsSize, &ctx->dnsCompletionEvent);

    return NABTO_EC_OK;
}

// Handle packet function
void nc_stun_handle_packet(struct nc_stun_context* ctx,
                           struct np_udp_endpoint* ep,
                           uint8_t* buffer,
                           uint16_t bufferSize)
{
    if (ctx->state == NC_STUN_STATE_ABORTED) {
        NABTO_LOG_ERROR(LOG, "Stun packet received for deinitialized stun context");
        return;
    }
    NABTO_LOG_TRACE(LOG, "Stun handling packet");
    nabto_stun_handle_packet(&ctx->stun, buffer, bufferSize);
    nc_stun_event(ctx);

}

void nc_stun_convert_ep(const struct nabto_stun_endpoint* stunEp, struct np_udp_endpoint* npEp )
{
    npEp->port = stunEp->port;
    if (stunEp->addr.type == NABTO_STUN_IPV4) {
        npEp->ip.type = NABTO_IPV4;
        memcpy(npEp->ip.ip.v4, stunEp->addr.v4.addr, 4);
    } else {
        npEp->ip.type = NABTO_IPV6;
        memcpy(npEp->ip.ip.v6, stunEp->addr.v6.addr, 16);
    }
}

void nc_stun_event_deferred(void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    nc_stun_event(ctx);
}

// event function
void nc_stun_event(struct nc_stun_context* ctx)
{
    enum nabto_stun_next_event_type event = nabto_stun_next_event_to_handle(&ctx->stun);
    struct np_platform* pl = ctx->pl;
    np_event_queue_cancel_timed_event(ctx->pl, ctx->toEv);
    switch(event) {
        case STUN_ET_SEND_PRIMARY:
        {
            if(!ctx->priUdp) {
                NABTO_LOG_ERROR(LOG, "No primary socket available");
                ctx->ec = NABTO_EC_UDP_SOCKET_ERROR;
                nc_stun_resolve_callbacks(ctx);
                return;
            }
            struct nabto_stun_endpoint stunEp;
            uint8_t* buffer = ctx->pl->buf.start(ctx->sendBuf);
            if(!nabto_stun_get_data_endpoint(&ctx->stun, &stunEp)) {
                NABTO_LOG_ERROR(LOG, "get endpoint failed");
                ctx->ec = NABTO_EC_NO_VALID_ENDPOINTS;
                nc_stun_resolve_callbacks(ctx);
                return;
            }
            ctx->sendEp.port = stunEp.port;
            if (stunEp.addr.type == NABTO_STUN_IPV4) {
                ctx->sendEp.ip.type = NABTO_IPV4;
                memcpy(ctx->sendEp.ip.ip.v4, stunEp.addr.v4.addr, 4);
            } else {
                ctx->sendEp.ip.type = NABTO_IPV6;
                memcpy(ctx->sendEp.ip.ip.v6, stunEp.addr.v6.addr, 16);
            }
            uint16_t wrote = nabto_stun_get_send_data(&ctx->stun, buffer, NABTO_STUN_BUFFER_SIZE);
            np_completion_event_init(pl, &ctx->sendCompletionEvent, &nc_stun_send_to_cb, ctx);
            nc_udp_dispatch_async_send_to(ctx->priUdp, &ctx->sendEp, pl->buf.start(ctx->sendBuf), wrote, &ctx->sendCompletionEvent);
            break;
        }
        case STUN_ET_SEND_SECONDARY:
        {
            if(!ctx->secUdp) {
                NABTO_LOG_ERROR(LOG, "No secondary socket available");
                ctx->ec = NABTO_EC_UDP_SOCKET_ERROR;
                nc_stun_resolve_callbacks(ctx);
                return;
            }
            struct nabto_stun_endpoint stunEp;
            uint8_t* buffer = ctx->pl->buf.start(ctx->sendBuf);
            if(!nabto_stun_get_data_endpoint(&ctx->stun, &stunEp)) {
                NABTO_LOG_ERROR(LOG, "get endpoint failed");
                ctx->ec = NABTO_EC_NO_VALID_ENDPOINTS;
                nc_stun_resolve_callbacks(ctx);
                return;
            }
            ctx->sendEp.port = stunEp.port;
            if (stunEp.addr.type == NABTO_STUN_IPV4) {
                ctx->sendEp.ip.type = NABTO_IPV4;
                memcpy(ctx->sendEp.ip.ip.v4, stunEp.addr.v4.addr, 4);
            } else {
                ctx->sendEp.ip.type = NABTO_IPV6;
                memcpy(ctx->sendEp.ip.ip.v6, stunEp.addr.v6.addr, 16);
            }
            uint16_t wrote = nabto_stun_get_send_data(&ctx->stun, buffer, NABTO_STUN_BUFFER_SIZE);
            np_completion_event_init(pl, &ctx->sendCompletionEvent, &nc_stun_send_to_cb, ctx);
            nc_udp_dispatch_async_send_to(ctx->secUdp, &ctx->sendEp, pl->buf.start(ctx->sendBuf), wrote, &ctx->sendCompletionEvent);
            break;
        }
        case STUN_ET_WAIT:
        {
            uint32_t to = nabto_stun_get_timeout_ms(&ctx->stun);
            np_event_queue_post_timed_event(ctx->pl, ctx->toEv, to);
        }
            break;
        case STUN_ET_NO_EVENT:
            NABTO_LOG_TRACE(LOG, "event state: STUN_ET_NO_EVENT");
            break;
        case STUN_ET_COMPLETED:
            ctx->state = NC_STUN_STATE_DONE;
            ctx->ec = NABTO_EC_OK;
            ctx->res = nabto_stun_get_result(&ctx->stun);
            nc_stun_resolve_callbacks(ctx);
            break;
        case STUN_ET_FAILED:
            ctx->ec = NABTO_EC_UNKNOWN;
            nc_stun_resolve_callbacks(ctx);
            break;
        default:
            NABTO_LOG_ERROR(LOG, "Found invalid event state %u", event);
            return;
    }
}

void nc_stun_dns_cb(const np_error_code ec, void* data)

{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    if (ctx->state == NC_STUN_STATE_ABORTED) {
        ctx->ec = NABTO_EC_ABORTED;
        nc_stun_resolve_callbacks(ctx);
        return;
    }
    if (ec != NABTO_EC_OK) {
        ctx->state = NC_STUN_STATE_DONE;
        ctx->ec = ec;
        nc_stun_resolve_callbacks(ctx);
        return;
    }
    ctx->numEps = nc_stun_convert_ep_list(ctx->resolvedIps, ctx->resolvedIpsSize, ctx->eps, NC_STUN_MAX_ENDPOINTS, ctx->priPort);
    nabto_stun_init(&ctx->stun, &ctx->stunModule, ctx, ctx->eps, ctx->numEps);
    nabto_stun_async_analyze(&ctx->stun, ctx->simple);
    nc_stun_event(ctx);
}

void nc_stun_send_to_cb(const np_error_code ec, void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    // send errors is ok in stun context
    nc_stun_event(ctx);
}

void nc_stun_handle_timeout(const np_error_code ec, void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    if (ec != NABTO_EC_OK) {
        ctx->state = NC_STUN_STATE_DONE;
        ctx->ec = ec;
        nc_stun_resolve_callbacks(ctx);
        return;
    }
    nabto_stun_handle_wait_event(&ctx->stun);
    nc_stun_event(ctx);

}

void nc_stun_analysed_cb(const np_error_code ec, const struct nabto_stun_result* res, void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    if (ctx->state == NC_STUN_STATE_ABORTED) {
        ctx->ec = NABTO_EC_ABORTED;
    } else {
        ctx->state = NC_STUN_STATE_DONE;
        ctx->ec = ec;
        ctx->res = res;
    }
    nc_stun_resolve_callbacks(ctx);
    return;
}

// util functions

void nc_stun_resolve_callbacks(void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    int i;
    nc_stun_analyze_callback cb;
    for (i = 0; i < NC_STUN_MAX_CALLBACKS; i++) {
        if (ctx->cbs[i].cb != NULL) {
            cb = ctx->cbs[i].cb;
            ctx->cbs[i].cb = NULL;
            cb(ctx->ec, ctx->res, ctx->cbs[i].data);
        }
    }
}

void nc_stun_set_endpoint(struct nabto_stun_endpoint* ep, struct np_ip_address* ip, uint16_t port)
{
    if (ip->type == NABTO_IPV4) {
        ep->addr.type = NABTO_STUN_IPV4;
        memcpy(ep->addr.v4.addr, ip->ip.v6, 4);
    } else if (ip->type == NABTO_IPV6) {
        ep->addr.type = NABTO_STUN_IPV6;
        memcpy(ep->addr.v6.addr, ip->ip.v6, 16);
    }
    ep->port = port;
}

size_t nc_stun_convert_ep_list(struct np_ip_address* ips, size_t ipsSize,
                               struct nabto_stun_endpoint* eps, size_t epsSize,
                               uint16_t port)
{
    size_t i;
    for (i = 0; i < ipsSize && i < epsSize; i++)
    {
        nc_stun_set_endpoint(&eps[i], &ips[i], port);
    }
    return i; // for increased index to count
}

uint16_t nc_stun_get_local_port(struct nc_stun_context* ctx)
{
    if(!ctx->priUdp) {
        NABTO_LOG_ERROR(LOG, "No primary socket available");
        return 0;
    }
    return nc_udp_dispatch_get_local_port(ctx->priUdp);
}
