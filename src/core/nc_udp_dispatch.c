#include "nc_udp_dispatch.h"

#include <platform/np_logging.h>
#include <platform/np_udp.h>
#include <platform/np_dtls_cli.h>

#include <core/nc_client_connection_dispatch.h>
#include <core/nc_stun.h>

#define LOG NABTO_LOG_MODULE_UDP_DISPATCH

void nc_udp_dispatch_sock_created_cb(const np_error_code ec, void* data);
void nc_udp_dispatch_handle_packet(const np_error_code ec, struct np_udp_endpoint ep,
                                   np_communication_buffer* buffer, uint16_t bufferSize, void* data);

void nc_udp_dispatch_init(struct nc_udp_dispatch_context* ctx, struct np_platform* pl)
{
    memset(ctx, 0, sizeof(struct nc_udp_dispatch_context));
    ctx->pl = pl;
    pl->udp.create(pl, &ctx->sock);
}

void nc_udp_dispatch_deinit(struct nc_udp_dispatch_context* ctx)
{
    struct np_platform* pl = ctx->pl;
    pl->udp.destroy(ctx->sock);
}


void nc_udp_dispatch_async_create (struct nc_udp_dispatch_context* ctx, struct np_platform* pl, uint16_t port,
                                   nc_udp_dispatch_create_callback cb, void* data)
{
    ctx->createCb = cb;
    ctx->createCbData = data;
    if (port == 0) {
        pl->udp.async_bind(ctx->sock, &nc_udp_dispatch_sock_created_cb, ctx);
    } else {
        pl->udp.async_bind_port(ctx->sock, port, &nc_udp_dispatch_sock_created_cb, ctx);
    }
}

void nc_udp_dispatch_sock_created_cb(const np_error_code ec, void* data)
{
    struct nc_udp_dispatch_context* ctx = (struct nc_udp_dispatch_context*) data;
    ctx->pl->udp.async_recv_from(ctx->sock, &nc_udp_dispatch_handle_packet, ctx);
    ctx->createCb(NABTO_EC_OK, ctx->createCbData);
}

void nc_udp_dispatch_async_send_to(struct nc_udp_dispatch_context* ctx,
                                   struct np_udp_send_context* sendCtx, struct np_udp_endpoint* ep,
                                   np_communication_buffer* buffer, uint16_t bufferSize,
                                   nc_udp_dispatch_send_callback cb, void* data)
{
    np_udp_populate_send_context(sendCtx, ctx->sock, *ep, buffer, bufferSize, cb, data);
    ctx->pl->udp.async_send_to(sendCtx);
}

uint16_t nc_udp_dispatch_get_local_port(struct nc_udp_dispatch_context* ctx)
{
    return ctx->pl->udp.get_local_port(ctx->sock);
}


void nc_udp_dispatch_handle_packet(const np_error_code ec, struct np_udp_endpoint ep,
                                   np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    struct nc_udp_dispatch_context* ctx = (struct nc_udp_dispatch_context*) data;
    uint8_t* start = ctx->pl->buf.start(buffer);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Socket returned error: %u", ec);
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
