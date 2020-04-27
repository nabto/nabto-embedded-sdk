#include "nc_rendezvous.h"

#include <core/nc_packet.h>
#include <core/nc_client_connection.h>
#include <core/nc_udp_dispatch.h>


#include <platform/np_logging.h>
#include <platform/np_completion_event.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_RENDEZVOUS

void nc_rendezvous_send_device_request(struct nc_rendezvous_context* ctx);

np_error_code nc_rendezvous_init(struct nc_rendezvous_context* ctx,
                                 struct np_platform* pl)
{
    memset(ctx, 0, sizeof(struct nc_rendezvous_context));
    ctx->priBuf = pl->buf.allocate();
    if (!ctx->priBuf) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->pl = pl;
    ctx->packetIndex = 0;
    ctx->sendingDevReqs = false;
    return NABTO_EC_OK;
}

void nc_rendezvous_deinit(struct nc_rendezvous_context* ctx)
{
    if (ctx->pl != NULL) { // if init called
        ctx->pl->buf.free(ctx->priBuf);
    }
}

void nc_rendezvous_set_udp_dispatch(struct nc_rendezvous_context* ctx, struct nc_udp_dispatch_context* udpDispatch)
{
    ctx->udpDispatch = udpDispatch;
}

void nc_rendezvous_remove_udp_dispatch(struct nc_rendezvous_context* ctx)
{
    ctx->udpDispatch = NULL;
}

void nc_rendezvous_handle_client_request(struct nc_rendezvous_context* ctx,
                                 np_udp_endpoint ep,
                                 uint8_t* connectionId)
{
    struct nc_rendezvous_send_packet packet;
    packet.type = CT_RENDEZVOUS_CLIENT_RESPONSE;
    memcpy(packet.connectionId, connectionId, 14);
    packet.ep = ep;
    nc_rendezvous_send_rendezvous(ctx, &packet);
}

void nc_rendezvous_packet_sent(const np_error_code ec, void* data)
{
    struct nc_rendezvous_context* ctx = (struct nc_rendezvous_context*)data;
    ctx->sendingDevReqs = false;
    nc_rendezvous_send_device_request(ctx);
}

void nc_rendezvous_send_device_request(struct nc_rendezvous_context* ctx)
{
    if (ctx->sendingDevReqs || !ctx->udpDispatch) {
        return;
    }
    uint8_t* start = ctx->pl->buf.start(ctx->priBuf);
    uint8_t* ptr = start;
    if (ctx->packetIndex <= 0) {
        return;
    }
    ctx->packetIndex -= 1;
    struct nc_rendezvous_send_packet* packet = &ctx->packetList[ctx->packetIndex];

    *ptr = NABTO_PROTOCOL_PREFIX_RENDEZVOUS;
    ptr++;
    memcpy(ptr, packet->connectionId, 14);
    ptr += 14;
    *ptr = 0;
    ptr++;

    *ptr = packet->type;
    ptr++;

    ctx->sendingDevReqs = true;
    size_t used = ptr - start;
    np_completion_event_init(ctx->pl, &ctx->sendCompletionEvent, nc_rendezvous_packet_sent, ctx);
    np_error_code ec = nc_udp_dispatch_async_send_to(ctx->udpDispatch, &packet->ep,
                                                     start, used, &ctx->sendCompletionEvent);

    if (ec != NABTO_EC_OK) {
        nc_rendezvous_packet_sent(ec, ctx);
    }
}

void nc_rendezvous_send_rendezvous(struct nc_rendezvous_context* ctx, struct nc_rendezvous_send_packet* packet)
{
    if (ctx->packetIndex >= NC_RENDEZVOUS_SEND_QUEUE_LENGTH) {
        // Queue is full, it's ok.
        return;
    }

    if (!ctx->udpDispatch) {
        // No way to send packets
        return;
    }

    ctx->packetList[ctx->packetIndex] = *packet;
    ctx->packetIndex++;
    nc_rendezvous_send_device_request(ctx);
}
