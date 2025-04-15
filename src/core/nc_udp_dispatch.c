#include "nc_udp_dispatch.h"

#include <platform/np_allocator.h>
#include <platform/np_dtls_cli.h>
#include <platform/np_logging.h>
#include <platform/np_udp_wrapper.h>

#include <core/nc_attacher.h>
#include <core/nc_client_connection_dispatch.h>
#include <core/nc_rendezvous.h>
#include <core/nc_stun.h>

#define LOG NABTO_LOG_MODULE_UDP_DISPATCH

void nc_udp_dispatch_sock_bound_cb(const np_error_code ec, void* data);
void nc_udp_dispatch_handle_packet(struct np_udp_endpoint* ep,
                                   uint8_t* buffer, uint16_t bufferSize, struct nc_udp_dispatch_context* ctx);

static void start_recv(struct nc_udp_dispatch_context* ctx);
static void async_recv_wait_complete(const np_error_code ec, void* userData);

np_error_code nc_udp_dispatch_init(struct nc_udp_dispatch_context* ctx, struct np_platform* pl, nc_udp_dispatch_event_listener listener, void* listenerData)
{
    memset(ctx, 0, sizeof(struct nc_udp_dispatch_context));
    np_error_code ec = np_udp_create(&pl->udp, &ctx->sock);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_completion_event_init(&pl->eq, &ctx->recvCompletionEvent, async_recv_wait_complete, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ctx->pl = pl;
    ctx->listener = listener;
    ctx->listenerData = listenerData;
    return NABTO_EC_OK;
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
    if (ec) {
        NABTO_LOG_TRACE(LOG, "recv wait completed with error code: %d", ec);
        ctx->listener(NC_DEVICE_EVENT_PLATFORM_FAILURE, ctx->listenerData);
        return;
    }

    struct np_udp_endpoint ep;
    size_t bufferLength = 1500;
    uint8_t* recvBuffer = np_calloc(1, bufferLength);
    size_t recvLength = 0;
    if (recvBuffer == NULL) {
        // We cannot allocate a sufficient large buffer for receiving the
        // packet, we do not want to stack allocate the large buffer as it makes
        // the system stack requirement large. We need to receive the packet but
        // we do it with a small buffer such that it will be discarded.
        uint8_t smallBuffer[1];
        // TODO: returned error code is ignored
        np_udp_recv_from(
            &ctx->pl->udp, ctx->sock, &ep, smallBuffer, sizeof(smallBuffer), &recvLength);
        NABTO_LOG_ERROR(LOG, "out of memory, discarding udp packet");
        start_recv(ctx);
        return;
    }
    np_error_code recvEc = np_udp_recv_from(
        &ctx->pl->udp, ctx->sock, &ep, recvBuffer, bufferLength, &recvLength);
    if (recvEc == NABTO_EC_OK) {
        nc_udp_dispatch_handle_packet(&ep, recvBuffer, (uint16_t)recvLength,
                                      ctx);
    }

    np_free(recvBuffer);

    if (recvEc == NABTO_EC_ABORTED) {
        return;
    }
    if (recvEc == NABTO_EC_OK || recvEc == NABTO_EC_AGAIN) {
        start_recv(ctx);
    } else {
        NABTO_LOG_ERROR(LOG, "udp recv from returned unexpected error: %d" )
        ctx->listener(NC_DEVICE_EVENT_PLATFORM_FAILURE, ctx->listenerData);
        return;
    }
}

void nc_udp_dispatch_handle_packet(struct np_udp_endpoint* ep,
                                   uint8_t* buffer, uint16_t bufferSize, struct nc_udp_dispatch_context* ctx)
{
    uint8_t* start = buffer;

    if (bufferSize < 1) {
        NABTO_LOG_ERROR(LOG, "Received empty udp packet from: %s, port: %d", np_ip_address_to_string(&ep->ip), ep->port);
        return;
    }

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
        NABTO_LOG_TRACE(LOG, "Unable to dispatch packet with starting byte: %u, size: %d, from: %s, port: %d, it is probably not an issue, since it is likely just a packet which has been sent to the socket for some reason.", start[0], bufferSize, np_ip_address_to_string(&ep->ip), ep->port);
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
