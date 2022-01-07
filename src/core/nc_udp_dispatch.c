#include "nc_udp_dispatch.h"

#include <platform/np_logging.h>
#include <platform/np_udp_wrapper.h>
#include <platform/np_dtls_cli.h>

#include <core/nc_client_connection_dispatch.h>
#include <core/nc_stun.h>
#include <core/nc_attacher.h>
#include <core/nc_rendezvous.h>

#define LOG NABTO_LOG_MODULE_UDP_DISPATCH

void nc_udp_dispatch_sock_bound_cb(const np_error_code ec, void* data);
void nc_udp_dispatch_handle_packet(struct np_udp_endpoint* ep,
                                   uint8_t* buffer, uint16_t bufferSize, struct nc_udp_dispatch_context* ctx);

static void start_recv(struct nc_udp_dispatch_context* ctx);
static void async_recv_wait_complete(const np_error_code ec, void* userData);

np_error_code nc_udp_dispatch_init(struct nc_udp_dispatch_context* ctx, struct np_platform* pl)
{
    memset(ctx, 0, sizeof(struct nc_udp_dispatch_context));
    ctx->pl = pl;
    np_error_code ec = np_udp_create(&pl->udp, &ctx->sock);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    return np_completion_event_init(&pl->eq, &ctx->recvCompletionEvent, async_recv_wait_complete, ctx);
}

void nc_udp_dispatch_deinit(struct nc_udp_dispatch_context* ctx)
{
    if (ctx->pl != NULL) { // if init was called
        struct np_platform* pl = ctx->pl;
        np_udp_destroy(&pl->udp, ctx->sock);
        np_completion_event_deinit(&ctx->recvCompletionEvent);
    }
}


void nc_udp_dispatch_async_bind(struct nc_udp_dispatch_context* ctx, struct np_platform* pl, uint16_t port,
                                struct np_completion_event* completionEvent)
{
    np_udp_async_bind_port(&pl->udp, ctx->sock, port, completionEvent);
}

void nc_udp_dispatch_start_recv(struct nc_udp_dispatch_context* ctx)
{
    start_recv(ctx);
}

np_error_code nc_udp_dispatch_abort(struct nc_udp_dispatch_context* ctx)
{
    np_udp_abort(&ctx->pl->udp, ctx->sock);
    return NABTO_EC_OK;
}

void nc_udp_dispatch_async_send_to(struct nc_udp_dispatch_context* ctx,struct np_udp_endpoint* ep,
                                   uint8_t* buffer, uint16_t bufferSize,
                                   struct np_completion_event* completionEvent)
{
    np_udp_async_send_to(&ctx->pl->udp, ctx->sock, ep, buffer, bufferSize, completionEvent);
}

uint16_t nc_udp_dispatch_get_local_port(struct nc_udp_dispatch_context* ctx)
{
    return np_udp_get_local_port(&ctx->pl->udp, ctx->sock);
}

void start_recv(struct nc_udp_dispatch_context* ctx)
{
    struct np_platform* pl = ctx->pl;
    np_udp_async_recv_wait(&pl->udp, ctx->sock, &ctx->recvCompletionEvent);
}

void async_recv_wait_complete(const np_error_code ec, void* userData)
{
    struct nc_udp_dispatch_context* ctx = userData;
    struct np_platform* pl = ctx->pl;
    if (ec) {
        return;
    }

    struct np_udp_endpoint ep;
    struct np_communication_buffer* recvBuffer = pl->buf.allocate();
    if (recvBuffer == NULL) {
        NABTO_LOG_ERROR(LOG, "Cannot allocate a buffer for receiving data, dropping packet.");
        start_recv(ctx);
    } else {
        uint8_t* bufferStart = pl->buf.start(recvBuffer);
        size_t bufferLength = pl->buf.size(recvBuffer);
        size_t recvLength;
        np_error_code recvEc = np_udp_recv_from(&ctx->pl->udp, ctx->sock, &ep, bufferStart, bufferLength, &recvLength);
        if (recvEc == NABTO_EC_OK) {
            nc_udp_dispatch_handle_packet(&ep, bufferStart, (uint16_t)recvLength, ctx);
        }
        pl->buf.free(recvBuffer);

        if (recvEc == NABTO_EC_OK || recvEc == NABTO_EC_AGAIN) {
            start_recv(ctx);
        }
    }

}

void nc_udp_dispatch_handle_packet(struct np_udp_endpoint* ep,
                                   uint8_t* buffer, uint16_t bufferSize, struct nc_udp_dispatch_context* ctx)
{
    uint8_t* start = buffer;

    // ec == OK
    if(ctx->stun != NULL && ((start[0] == 0) || (start[0] == 1))) {
        nc_stun_handle_packet(ctx->stun, ep, buffer, bufferSize);
    }  else if (ctx->attacher != NULL && ((start[0] >= 20)  && (start[0] <= 64))) {
        nc_attacher_handle_dtls_packet(ctx->attacher, ep, buffer, bufferSize);
    } else if (ctx->cliConn != NULL && (start[0] == 240)) {
        nc_client_connection_dispatch_handle_packet(ctx->cliConn, ctx, ep, buffer, bufferSize);
    } else if (ctx->rendezvous != NULL && (start[0] == 241)) {
        nc_rendezvous_handle_packet(ctx->rendezvous, ctx, ctx->cliConn, ep, buffer, bufferSize);
    } else {
        NABTO_LOG_ERROR(LOG, "Unable to dispatch packet with ID: %u", start[0]);
    }
}

void nc_udp_dispatch_set_client_connection_context(struct nc_udp_dispatch_context* ctx,
                                                   struct nc_client_connection_dispatch_context* cliConn)
{
    ctx->cliConn = cliConn;
}

void nc_udp_dispatch_set_attach_context(struct nc_udp_dispatch_context* ctx,
                                        struct nc_attach_context* attacher)
{
    ctx->attacher = attacher;
}

void nc_udp_dispatch_set_stun_context(struct nc_udp_dispatch_context* ctx,
                                      struct nc_stun_context* stun)
{
    ctx->stun = stun;
}

void nc_udp_dispatch_set_rendezvous_context(struct nc_udp_dispatch_context* ctx,
                                            struct nc_rendezvous_context* rendezvous)
{
    ctx->rendezvous = rendezvous;
}

void nc_udp_dispatch_clear_client_connection_context(struct nc_udp_dispatch_context* ctx)
{
    ctx->cliConn = NULL;
}

void nc_udp_dispatch_clear_attacher_context(struct nc_udp_dispatch_context* ctx)
{
    ctx->attacher = NULL;
}

void nc_udp_dispatch_clear_stun_context(struct nc_udp_dispatch_context* ctx)
{
    ctx->stun = NULL;
}

void nc_udp_dispatch_clear_rendezvous_context(struct nc_udp_dispatch_context* ctx)
{
    ctx->rendezvous = NULL;
}
