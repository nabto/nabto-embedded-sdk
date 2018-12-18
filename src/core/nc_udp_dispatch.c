#include "nc_udp_dispatch.h"

#include <platform/np_logging.h>
#include <platform/np_udp.h>
#include <platform/np_dtls_cli.h>

#include <core/nc_client_connect_dispatch.h>

#define LOG NABTO_LOG_MODULE_UDP_DISPATCH

void nc_udp_dispatch_sock_created_cb(const np_error_code ec, np_udp_socket* socket, void* data);
void nc_udp_dispatch_handle_packet(const np_error_code ec, struct np_udp_endpoint ep,
                                   np_communication_buffer* buffer, uint16_t bufferSize, void* data);

void nc_udp_dispatch_cancel_send_to(struct nc_udp_dispatch_context* ctx)
{
    ctx->pl->udp.cancel_send_to(ctx->sock);
}


void nc_udp_dispatch_async_create (struct nc_udp_dispatch_context* ctx, struct np_platform* pl,
                                   nc_udp_dispatch_create_callback cb, void* data)
{
    memset(ctx, 0, sizeof(struct nc_udp_dispatch_context));
    ctx->pl = pl;
    ctx->createCb = cb;
    ctx->createCbData = data;
    pl->udp.async_create(&nc_udp_dispatch_sock_created_cb, ctx);
}

void nc_udp_dispatch_sock_destroyed_cb(const np_error_code ec, void* data)
{
    struct nc_udp_dispatch_context* ctx = (struct nc_udp_dispatch_context*)data;
    NABTO_LOG_TRACE(LOG, "Socket destroyed");
    ctx->sock = NULL;
    ctx->destroyCb(ec, ctx->destroyCbData);
}

void nc_udp_dispatch_async_destroy(struct nc_udp_dispatch_context* ctx,
                                   nc_udp_dispatch_destroy_callback cb, void* data)
{
    NABTO_LOG_TRACE(LOG, "Destroying socket");
    ctx->destroyCb = cb;
    ctx->destroyCbData = data;
    ctx->pl->udp.async_destroy(ctx->sock, &nc_udp_dispatch_sock_destroyed_cb, data);
}

void nc_udp_dispatch_sock_created_cb(const np_error_code ec, np_udp_socket* socket, void* data)
{
    struct nc_udp_dispatch_context* ctx = (struct nc_udp_dispatch_context*) data;
    ctx->sock = socket;
    ctx->pl->udp.async_recv_from(ctx->sock, &nc_udp_dispatch_handle_packet, ctx);
    ctx->createCb(NABTO_EC_OK, ctx->createCbData);
}

void nc_udp_dispatch_async_send_to(struct nc_udp_dispatch_context* ctx, struct np_udp_endpoint* ep,
                                   np_communication_buffer* buffer, uint16_t bufferSize,
                                   nc_udp_dispatch_send_callback cb, void* data)
{
    ctx->pl->udp.async_send_to(ctx->sock, ep, buffer, bufferSize, cb, data);
}


void nc_udp_dispatch_handle_packet(const np_error_code ec, struct np_udp_endpoint ep,
                                   np_communication_buffer* buffer, uint16_t bufferSize, void* data)
{
    struct nc_udp_dispatch_context* ctx = (struct nc_udp_dispatch_context*) data;
    uint8_t* start = ctx->pl->buf.start(buffer);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Socker returned error: %u", ec);
        return;
    }
    if(ctx->stun != NULL && ((start[0] == 0) || (start[0] == 1))) {
        // TODO: call stun module once implemented
        NABTO_LOG_ERROR(LOG, "Unable to dispatch stun packet");
    }  else if (ctx->dtls != NULL && ((start[0] >= 20)  && (start[0] <= 64))) {
        ctx->pl->dtlsC.handle_packet(ctx->pl, ctx->dtls, buffer, bufferSize);
    } else if (ctx->cliConn != NULL && (start[0] == 240)) {
        nc_client_connect_dispatch_handle_packet(ctx->cliConn, ctx, ep, buffer, bufferSize);
    } else {
        NABTO_LOG_ERROR(LOG, "Unable to dispatch packet with ID: %u", start[0]);
    }
    ctx->pl->udp.async_recv_from(ctx->sock, &nc_udp_dispatch_handle_packet, ctx);
}

void nc_udp_dispatch_set_client_connect_context(struct nc_udp_dispatch_context* ctx,
                                                struct nc_client_connect_dispatch_context* cliConn)
{
    ctx->cliConn = cliConn;
}

void nc_udp_dispatch_set_dtls_cli_context(struct nc_udp_dispatch_context* ctx,
                                          struct np_dtls_cli_context* dtls)
{
    ctx->dtls = dtls;
}

// TODO: fix stun type when stun is implemented
void nc_udp_dispatch_set_stun_context(struct nc_udp_dispatch_context* ctx,
                                      void* stun)
{
    ctx->stun = stun;
}

void nc_udp_dispatch_clear_client_connect_context(struct nc_udp_dispatch_context* ctx)
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
