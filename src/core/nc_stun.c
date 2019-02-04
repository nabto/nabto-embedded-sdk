#include "nc_stun.h"
#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_STUN

#ifndef NABTO_STUN_BUFFER_SIZE
#define NABTO_STUN_BUFFER_SIZE 512
#endif

// util functions
void nc_stun_resolve_callbacks(void* data);
size_t nc_stun_convert_ep_list(struct np_ip_address* rec, size_t recSize,
                             struct nabto_stun_endpoint* eps, size_t epsSize,
                             uint16_t port);
void nc_stun_event(struct nc_stun_context* ctx);

// Async callback functions
void nc_stun_udp_created_cb(const np_error_code ec, void* data);
void nc_stun_udp_destroyed_cb(const np_error_code ec, void* data);
void nc_stun_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data);
void nc_stun_analysed_cb(const np_error_code ec, const struct nabto_stun_result* res, void* data);
void nc_stun_send_to_cb(const np_error_code ec, void* data);
void nc_stun_handle_timeout(const np_error_code ec, void* data);

// stun module functions
uint32_t nc_stun_get_stamp(void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    return ctx->pl->ts.now_ms();
}
void nc_stun_log(const char* file, int line, enum nabto_stun_log_level level,
                 const char* fmt, va_list args, void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    if (level == NABTO_STUN_LOG_LEVEL_INFO) {
        np_log.log(NABTO_LOG_SEVERITY_INFO, LOG, line, file, fmt, args);
    } else if (level == NABTO_STUN_LOG_LEVEL_TRACE) {
        np_log.log(NABTO_LOG_SEVERITY_TRACE, LOG, line, file, fmt, args);

    } else if (level == NABTO_STUN_LOG_LEVEL_DEBUG) {
        np_log.log(NABTO_LOG_SEVERITY_DEBUG, LOG, line, file, fmt, args);

    } else if (level == NABTO_STUN_LOG_LEVEL_ERROR) {
        np_log.log(NABTO_LOG_SEVERITY_ERROR, LOG, line, file, fmt, args);

    } 
}

// TODO: DONT USE RAND
#include <stdlib.h> 

bool nc_stun_get_rand(uint8_t* buf, uint16_t size, void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    int i;
    for ( i = 0; i < size; i++) {
        *buf = (uint8_t)rand();
        buf++;
    }
    return true;
}

// init function
void nc_stun_init(struct nc_stun_context* ctx,
                  struct np_platform* pl,
                  const char* hostname, 
                  struct nc_udp_dispatch_context* udp)
{
    memset(ctx, 0, sizeof(struct nc_stun_context));
    srand(pl->ts.now_ms());
    ctx->pl = pl;
    ctx->priUdp = udp;
    ctx->state = NC_STUN_STATE_NONE;
    ctx->hostname = hostname;
    ctx->sendBuf = pl->buf.allocate();
    ctx->stunModule.get_stamp = &nc_stun_get_stamp;
    ctx->stunModule.log = &nc_stun_log;
    ctx->stunModule.get_rand = &nc_stun_get_rand;
}

// analyze function
np_error_code nc_stun_async_analyze(struct nc_stun_context* ctx,
                                    nc_stun_analyze_callback cb, void* data)
{
    int i;
    bool found = false;
    NABTO_LOG_INFO(LOG, "Starting STUN analysis");
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
        return NABTO_EC_FAILED;
    }
    if (ctx->state == NC_STUN_STATE_RUNNING) {
        NABTO_LOG_INFO(LOG, "Stun already running, adding callback");
        return NABTO_EC_OK;
    }
    /*if (ctx->state == NC_STUN_STATE_DONE) {
        np_event_queue_post(ctx->pl, &ctx->resultEv, &nc_stun_resolve_callbacks, ctx);
        return NABTO_EC_OK;
        }*/
    ctx->state = NC_STUN_STATE_RUNNING;
    nc_udp_dispatch_async_create(&ctx->secUdp, ctx->pl, &nc_stun_udp_created_cb, ctx);
    return NABTO_EC_OK;
}

// Handle packet function
void nc_stun_handle_packet(struct nc_stun_context* ctx,
                           struct np_udp_endpoint ep,
                           np_communication_buffer* buffer,
                           uint16_t bufferSize)
{
    NABTO_LOG_TRACE(LOG, "Stun handling packet");
    nabto_stun_handle_packet(&ctx->stun, ctx->pl->buf.start(buffer), bufferSize);
    nc_stun_event(ctx);

}

// event function
void nc_stun_event(struct nc_stun_context* ctx)
{
    enum nabto_stun_next_event_type event = nabto_stun_next_event_to_handle(&ctx->stun);
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->toEv);
    switch(event) {
        case STUN_ET_SEND_PRIMARY:
        {
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
                memcpy(ctx->sendEp.ip.v4.addr, stunEp.addr.v4.addr, 4);
            } else {
                ctx->sendEp.ip.type = NABTO_IPV6;
                memcpy(ctx->sendEp.ip.v6.addr, stunEp.addr.v6.addr, 16);
            }
            uint16_t wrote = nabto_stun_get_send_data(&ctx->stun, buffer, NABTO_STUN_BUFFER_SIZE);
            NABTO_LOG_TRACE(LOG, "Sending stun packet");
            nc_udp_dispatch_async_send_to(ctx->priUdp, &ctx->sendCtx, &ctx->sendEp, ctx->sendBuf, wrote, &nc_stun_send_to_cb, ctx);
            break;
        }
        case STUN_ET_SEND_SECONDARY:
        {
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
                memcpy(ctx->sendEp.ip.v4.addr, stunEp.addr.v4.addr, 4);
            } else {
                ctx->sendEp.ip.type = NABTO_IPV6;
                memcpy(ctx->sendEp.ip.v6.addr, stunEp.addr.v6.addr, 16);
            }
            uint16_t wrote = nabto_stun_get_send_data(&ctx->stun, buffer, NABTO_STUN_BUFFER_SIZE);
            NABTO_LOG_TRACE(LOG, "Sending stun packet");
            nc_udp_dispatch_async_send_to(&ctx->secUdp, &ctx->sendCtx, &ctx->sendEp, ctx->sendBuf, wrote, &nc_stun_send_to_cb, ctx);
            break;
        }
        case STUN_ET_WAIT:
        {
            NABTO_LOG_TRACE(LOG, "event state: STUN_ET_WAIT");
            uint32_t to = nabto_stun_get_timeout_ms(&ctx->stun);
            np_event_queue_post_timed_event(ctx->pl, &ctx->toEv, to, &nc_stun_handle_timeout, ctx);
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
            nc_udp_dispatch_async_destroy(&ctx->secUdp, &nc_stun_udp_destroyed_cb, ctx);
            break;
        case STUN_ET_FAILED:
            ctx->ec = NABTO_EC_FAILED;
            nc_stun_resolve_callbacks(ctx);
            break;
        default:
            NABTO_LOG_ERROR(LOG, "Found invalid event state %u", event);
            return;
    }
}

// async callback functions
void nc_stun_udp_created_cb(const np_error_code ec, void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    if (ec != NABTO_EC_OK) {
        ctx->state = NC_STUN_STATE_DONE;
        ctx->ec = ec;
        nc_stun_resolve_callbacks(ctx);
        return;
    }
    nc_udp_dispatch_set_stun_context(ctx->priUdp, ctx);
    nc_udp_dispatch_set_stun_context(&ctx->secUdp, ctx);
    ctx->pl->dns.async_resolve(ctx->pl, ctx->hostname, &nc_stun_dns_cb, ctx);
}

void nc_stun_udp_destroyed_cb(const np_error_code ec, void* data)
{
    NABTO_LOG_TRACE(LOG, "UDP socket destroyed");
}

void nc_stun_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    if (ec != NABTO_EC_OK) {
        ctx->state = NC_STUN_STATE_DONE;
        ctx->ec = ec;
        nc_stun_resolve_callbacks(ctx);
        return;
    }
    ctx->numEps = nc_stun_convert_ep_list(rec, recSize, ctx->eps, NC_STUN_MAX_ENDPOINTS, NC_STUN_PORT);
    nabto_stun_init(&ctx->stun, &ctx->stunModule, ctx, ctx->eps, ctx->numEps);
    nabto_stun_async_analyze(&ctx->stun);
    nc_stun_event(ctx);
}

void nc_stun_send_to_cb(const np_error_code ec, void* data)
{
    struct nc_stun_context* ctx = (struct nc_stun_context*)data;
    if (ec != NABTO_EC_OK) {
        ctx->state = NC_STUN_STATE_DONE;
        ctx->ec = ec;
        nc_stun_resolve_callbacks(ctx);
        return;
    }
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
    ctx->state = NC_STUN_STATE_DONE;
    ctx->ec = ec;
    ctx->res = res;
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

size_t nc_stun_convert_ep_list(struct np_ip_address* rec, size_t recSize,
                             struct nabto_stun_endpoint* eps, size_t epsSize,
                             uint16_t port)
{
    size_t end;
    int i;
    if (recSize > epsSize) {
        end = epsSize;
    } else {
        end = recSize;
    }
    for (i = 0; i < end; i++) {
        eps[i].port = port;
        if (rec[i].type == NABTO_IPV4) {
            eps[i].addr.type = NABTO_STUN_IPV4;
            memcpy(eps[i].addr.v4.addr, rec[i].v4.addr, 4);
        } else if (rec[i].type == NABTO_IPV6) {
            eps[i].addr.type = NABTO_STUN_IPV6;
            memcpy(eps[i].addr.v6.addr, rec[i].v6.addr, 16);
        }
    }
    return end;
}

