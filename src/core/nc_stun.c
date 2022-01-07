#include "nc_stun.h"
#include "nc_device.h"

#include <platform/np_logging.h>
#include <platform/np_timestamp_wrapper.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_allocator.h>

#include <string.h>
#include <nn/string.h>

#define LOG NABTO_LOG_MODULE_STUN

#ifndef NABTO_STUN_BUFFER_SIZE
#define NABTO_STUN_BUFFER_SIZE 512
#endif

// util functions
void nc_stun_resolve_callbacks(struct nc_stun_context* ctx);
size_t nc_stun_convert_ep_list(struct np_ip_address* ips, size_t ipsSize,
                               struct nn_endpoint* eps, size_t epsSize,
                               uint16_t port);
void nc_stun_event(struct nc_stun_context* ctx);

// Async callback functions
void nc_stun_analysed_cb(const np_error_code ec, const struct nabto_stun_result* res, void* data);
void nc_stun_send_to_cb(const np_error_code ec, void* data);
void nc_stun_handle_timeout(void* data);
static void nc_stun_dns_cb(const np_error_code ec, void* data);

// stun module functions
uint32_t nc_stun_get_stamp(void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    return np_timestamp_now_ms(&ctx->pl->timestamp);
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
                           struct nc_device_context* device,
                           struct np_platform* pl)
{
    memset(ctx, 0, sizeof(struct nc_stun_context));
    ctx->sendBuf = pl->buf.allocate();
    if (!ctx->sendBuf) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    struct np_event_queue* eq = &pl->eq;

    ctx->pl = pl;
    ctx->state = NC_STUN_STATE_NONE;
    ctx->stunModule.get_stamp = &nc_stun_get_stamp;
    ctx->stunModule.logger = &device->moduleLogger;
    ctx->stunModule.get_rand = &nc_stun_get_rand;
    np_error_code ec;
    ec = np_event_queue_create_event(eq, &nc_stun_handle_timeout, ctx, &ctx->toEv);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = nc_dns_multi_resolver_init(pl, &ctx->dnsMultiResolver);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_completion_event_init(eq, &ctx->dnsCompletionEvent, &nc_stun_dns_cb, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_completion_event_init(eq, &ctx->sendCompletionEvent, &nc_stun_send_to_cb, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    nn_llist_init(&ctx->cbs);
    ctx->initialized = true;
    return NABTO_EC_OK;
}

void nc_stun_stop(struct nc_stun_context* ctx)
{
    // TODO stop current stun requests if any
    ctx->state = NC_STUN_STATE_ABORTED;
    ctx->ec = NABTO_EC_ABORTED;
    nc_stun_resolve_callbacks(ctx);
}

void nc_stun_deinit(struct nc_stun_context* ctx)
{
    if (ctx->initialized) { // if init called
        ctx->state = NC_STUN_STATE_ABORTED;
        struct np_platform* pl = ctx->pl;
        pl->buf.free(ctx->sendBuf);

        np_event_queue_destroy_event(&pl->eq, ctx->toEv);
        np_completion_event_deinit(&ctx->dnsCompletionEvent);
        np_completion_event_deinit(&ctx->sendCompletionEvent);
        nc_dns_multi_resolver_deinit(&ctx->dnsMultiResolver);
        if (ctx->hostname != NULL) {
            np_free((void*)ctx->hostname);
        }
        ctx->initialized = false;
    }
}

void nc_stun_set_sockets(struct nc_stun_context* ctx, struct nc_udp_dispatch_context* udp, struct nc_udp_dispatch_context* secondaryUdp)
{
    ctx->priUdp = udp;
    ctx->secUdp = secondaryUdp;
}
void nc_stun_set_host(struct nc_stun_context* ctx, const char* hostname, uint16_t port)
{
    if (ctx->initialized) {
        ctx->hostname = nn_strdup(hostname, np_allocator_get());
        ctx->priPort = port;
    }
}

void nc_stun_remove_sockets(struct nc_stun_context* ctx)
{
    ctx->priUdp = NULL;
    ctx->secUdp = NULL;
}

// analyze function
np_error_code nc_stun_async_analyze_simple(struct nc_stun_context* ctx, struct nc_stun_callback* callback,
                                           nc_stun_analyze_callback cb, void* data)
{
    callback->cb = cb;
    callback->data = data;

    if (ctx->state == NC_STUN_STATE_ABORTED) {
        return NABTO_EC_ABORTED;
    }
    NABTO_LOG_TRACE(LOG, "Starting STUN analysis for host: %s", ctx->hostname);
    if (ctx->hostname == NULL) {
        NABTO_LOG_ERROR(LOG, "Stun analysis started before host was configured");
        return NABTO_EC_INVALID_STATE;
    }
    nn_llist_append(&ctx->cbs, &callback->callbackNode, callback);

    if (ctx->state == NC_STUN_STATE_RUNNING) {
        NABTO_LOG_INFO(LOG, "Stun already running, adding callback");
        return NABTO_EC_OK;
    }

    ctx->simple = true;
    ctx->state = NC_STUN_STATE_RUNNING;
    nc_dns_multi_resolver_resolve(&ctx->dnsMultiResolver, ctx->hostname, ctx->resolvedIps, NC_STUN_MAX_ENDPOINTS, &ctx->resolvedIpsSize, &ctx->dnsCompletionEvent);

    return NABTO_EC_OK;
}

// Handle packet function
void nc_stun_handle_packet(struct nc_stun_context* ctx,
                           struct np_udp_endpoint* ep,
                           uint8_t* buffer,
                           uint16_t bufferSize)
{
    (void)ep;
    if (ctx->state == NC_STUN_STATE_ABORTED) {
        NABTO_LOG_ERROR(LOG, "Stun packet received for deinitialized stun context");
        return;
    }
    NABTO_LOG_TRACE(LOG, "Stun handling packet");
    nabto_stun_handle_packet(&ctx->stun, buffer, bufferSize);
    nc_stun_event(ctx);

}

void nc_stun_convert_ep(const struct nn_endpoint* stunEp, struct np_udp_endpoint* npEp )
{
    npEp->port = stunEp->port;
    if (stunEp->ip.type == NN_IPV4) {
        npEp->ip.type = NABTO_IPV4;
        memcpy(npEp->ip.ip.v4, stunEp->ip.ip.v4, 4);
    } else {
        npEp->ip.type = NABTO_IPV6;
        memcpy(npEp->ip.ip.v6, stunEp->ip.ip.v6, 16);
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
    np_event_queue_cancel_event(&ctx->pl->eq, ctx->toEv);
    switch(event) {
        case STUN_ET_SEND_PRIMARY:
        {
            if(!ctx->priUdp) {
                NABTO_LOG_ERROR(LOG, "No primary socket available");
                ctx->ec = NABTO_EC_UDP_SOCKET_ERROR;
                nc_stun_resolve_callbacks(ctx);
                return;
            }
            struct nn_endpoint stunEp;
            uint8_t* buffer = ctx->pl->buf.start(ctx->sendBuf);
            if(!nabto_stun_get_data_endpoint(&ctx->stun, &stunEp)) {
                NABTO_LOG_ERROR(LOG, "get endpoint failed");
                ctx->ec = NABTO_EC_NO_VALID_ENDPOINTS;
                nc_stun_resolve_callbacks(ctx);
                return;
            }
            ctx->sendEp.port = stunEp.port;
            if (stunEp.ip.type == NN_IPV4) {
                ctx->sendEp.ip.type = NABTO_IPV4;
                memcpy(ctx->sendEp.ip.ip.v4, stunEp.ip.ip.v4, 4);
            } else {
                ctx->sendEp.ip.type = NABTO_IPV6;
                memcpy(ctx->sendEp.ip.ip.v6, stunEp.ip.ip.v6, 16);
            }
            uint16_t wrote = nabto_stun_get_send_data(&ctx->stun, buffer, NABTO_STUN_BUFFER_SIZE);
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
            struct nn_endpoint stunEp;
            uint8_t* buffer = ctx->pl->buf.start(ctx->sendBuf);
            if(!nabto_stun_get_data_endpoint(&ctx->stun, &stunEp)) {
                NABTO_LOG_ERROR(LOG, "get endpoint failed");
                ctx->ec = NABTO_EC_NO_VALID_ENDPOINTS;
                nc_stun_resolve_callbacks(ctx);
                return;
            }
            ctx->sendEp.port = stunEp.port;
            if (stunEp.ip.type == NN_IPV4) {
                ctx->sendEp.ip.type = NABTO_IPV4;
                memcpy(ctx->sendEp.ip.ip.v4, stunEp.ip.ip.v4, 4);
            } else {
                ctx->sendEp.ip.type = NABTO_IPV6;
                memcpy(ctx->sendEp.ip.ip.v6, stunEp.ip.ip.v6, 16);
            }
            uint16_t wrote = nabto_stun_get_send_data(&ctx->stun, buffer, NABTO_STUN_BUFFER_SIZE);
            nc_udp_dispatch_async_send_to(ctx->secUdp, &ctx->sendEp, pl->buf.start(ctx->sendBuf), wrote, &ctx->sendCompletionEvent);
            break;
        }
        case STUN_ET_WAIT:
        {
            uint32_t to = nabto_stun_get_timeout_ms(&ctx->stun);
            np_event_queue_post_timed_event(&ctx->pl->eq, ctx->toEv, to);
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
    nabto_stun_init(&ctx->stun, &ctx->stunModule, ctx, ctx->eps, (uint8_t)ctx->numEps);
    nabto_stun_async_analyze(&ctx->stun, ctx->simple);
    nc_stun_event(ctx);
}

void nc_stun_send_to_cb(const np_error_code ec, void* data)
{
    (void)ec;
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    // send errors is ok in stun context
    nc_stun_event(ctx);
}

void nc_stun_handle_timeout(void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
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

void nc_stun_resolve_callbacks(struct nc_stun_context* ctx)
{
    struct nn_llist_iterator it = nn_llist_begin(&ctx->cbs);

    while(!nn_llist_is_end(&it)) {
        struct nc_stun_callback* cb = nn_llist_get_item(&it);
        nn_llist_next(&it);
        nn_llist_erase_node(&cb->callbackNode);
        cb->cb(ctx->ec, ctx->res, cb->data);
    }
}

void nc_stun_set_endpoint(struct nn_endpoint* ep, struct np_ip_address* ip, uint16_t port)
{
    if (ip->type == NABTO_IPV4) {
        ep->ip.type = NN_IPV4;
        memcpy(ep->ip.ip.v4, ip->ip.v6, 4);
    } else if (ip->type == NABTO_IPV6) {
        ep->ip.type = NN_IPV6;
        memcpy(ep->ip.ip.v6, ip->ip.v6, 16);
    }
    ep->port = port;
}

size_t nc_stun_convert_ep_list(struct np_ip_address* ips, size_t ipsSize,
                               struct nn_endpoint* eps, size_t epsSize,
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
