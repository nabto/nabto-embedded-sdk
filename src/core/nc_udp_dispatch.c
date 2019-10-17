#include "nc_udp_dispatch.h"

#include <platform/np_logging.h>
#include <platform/np_udp.h>
#include <platform/np_dtls_cli.h>

#include <core/nc_client_connection_dispatch.h>
#include <core/nc_stun.h>

#define LOG NABTO_LOG_MODULE_UDP_DISPATCH
// todo rename and restructure with new udp return values
void nc_udp_dispatch_sock_bound_cb(const np_error_code ec, void* data);
void nc_udp_dispatch_handle_packet(const np_error_code ec, struct np_udp_endpoint ep,
                                   uint8_t* buffer, uint16_t bufferSize, void* data);

np_error_code nc_udp_dispatch_init(struct nc_udp_dispatch_context* ctx, struct np_platform* pl)
{
    memset(ctx, 0, sizeof(struct nc_udp_dispatch_context));
    ctx->pl = pl;
    return pl->udp.create(pl, &ctx->sock);
}

void nc_udp_dispatch_deinit(struct nc_udp_dispatch_context* ctx)
{
    struct np_platform* pl = ctx->pl;
    pl->udp.destroy(ctx->sock);
}


np_error_code nc_udp_dispatch_async_bind(struct nc_udp_dispatch_context* ctx, struct np_platform* pl, uint16_t port,
                                         nc_udp_dispatch_bind_callback cb, void* data)
{
    ctx->bindCb = cb;
    ctx->bindCbData = data;
    return pl->udp.async_bind_port(ctx->sock, port, &nc_udp_dispatch_sock_bound_cb, ctx);
}

void nc_udp_dispatch_sock_bound_cb(const np_error_code ec, void* data)
{
    struct nc_udp_dispatch_context* ctx = (struct nc_udp_dispatch_context*) data;
    if (ec == NABTO_EC_OK) {
        ctx->pl->udp.async_recv_from(ctx->sock, &nc_udp_dispatch_handle_packet, ctx);
    }
    ctx->bindCb(ec, ctx->bindCbData);
    ctx->bindCb = NULL;
}

np_error_code nc_udp_dispatch_abort(struct nc_udp_dispatch_context* ctx)
{
    return ctx->pl->udp.abort(ctx->sock);
}

np_error_code nc_udp_dispatch_async_send_to(struct nc_udp_dispatch_context* ctx,struct np_udp_endpoint* ep,
                                            uint8_t* buffer, uint16_t bufferSize,
                                            nc_udp_dispatch_send_callback cb, void* data)
{
    return ctx->pl->udp.async_send_to(ctx->sock, *ep, buffer, bufferSize, cb, data);
}

uint16_t nc_udp_dispatch_get_local_port(struct nc_udp_dispatch_context* ctx)
{
    return ctx->pl->udp.get_local_port(ctx->sock);
}


void nc_udp_dispatch_handle_packet(const np_error_code ec, struct np_udp_endpoint ep,
                                   uint8_t* buffer, uint16_t bufferSize, void* data)
{
    struct nc_udp_dispatch_context* ctx = (struct nc_udp_dispatch_context*) data;
    uint8_t* start = buffer;
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Socket returned error: (%u) %s", ec, np_error_code_to_string(ec));
        return;
    }
    if(ctx->stun != NULL && ((start[0] == 0) || (start[0] == 1))) {
        nc_stun_handle_packet(ctx->stun, ep, buffer, bufferSize);
    }  else if (ctx->dtls != NULL && ((start[0] >= 20)  && (start[0] <= 64))) {
        ctx->pl->dtlsC.handle_packet(ctx->pl, ctx->dtls, buffer, bufferSize);
    } else if (ctx->cliConn != NULL && (start[0] >= 240)) {
        nc_client_connection_dispatch_handle_packet(ctx->cliConn, ctx, ep, buffer, bufferSize);
    } else {
        NABTO_LOG_ERROR(LOG, "Unable to dispatch packet with ID: %u", start[0]);
    }
    ctx->pl->udp.async_recv_from(ctx->sock, &nc_udp_dispatch_handle_packet, ctx);
}

void nc_udp_dispatch_set_client_connection_context(struct nc_udp_dispatch_context* ctx,
                                                   struct nc_client_connection_dispatch_context* cliConn)
{
    ctx->cliConn = cliConn;
}

void nc_udp_dispatch_set_dtls_cli_context(struct nc_udp_dispatch_context* ctx,
                                          struct np_dtls_cli_context* dtls)
{
    ctx->dtls = dtls;
}

void nc_udp_dispatch_set_stun_context(struct nc_udp_dispatch_context* ctx,
                                      struct nc_stun_context* stun)
{
    ctx->stun = stun;
}

void nc_udp_dispatch_clear_client_connection_context(struct nc_udp_dispatch_context* ctx)
{
    ctx->cliConn = NULL;
}

void nc_udp_dispatch_clear_dtls_cli_context(struct nc_udp_dispatch_context* ctx)
{
    ctx->dtls = NULL;
}

void nc_udp_dispatch_clear_stun_context(struct nc_udp_dispatch_context* ctx)
{
    ctx->stun = NULL;
}
