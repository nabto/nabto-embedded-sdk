#include "nc_rendezvous.h"

#include <core/nc_client_connection.h>
#include <core/nc_client_connection_dispatch.h>
#include <core/nc_packet.h>
#include <core/nc_udp_dispatch.h>


#include <platform/np_completion_event.h>
#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_RENDEZVOUS

static void nc_rendezvous_send_device_request(struct nc_rendezvous_context* ctx);
static void nc_rendezvous_packet_sent(const np_error_code ec, void* data);

np_error_code nc_rendezvous_init(struct nc_rendezvous_context* ctx,
                                 struct np_platform* pl)
{
    memset(ctx, 0, sizeof(struct nc_rendezvous_context));
    ctx->sendBuffer = NULL;
    np_error_code ec = np_completion_event_init(&pl->eq, &ctx->sendCompletionEvent, nc_rendezvous_packet_sent, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ctx->pl = pl;
    ctx->packetIndex = 0;
    ctx->sendingDevReqs = false;
    return NABTO_EC_OK;
}

void nc_rendezvous_deinit(struct nc_rendezvous_context* ctx)
{
    if (ctx->pl != NULL) { // if init called
        np_completion_event_deinit(&ctx->sendCompletionEvent);
        ctx->pl->buf.free(ctx->sendBuffer);
    }
}

void nc_rendezvous_set_udp_dispatch(struct nc_rendezvous_context* ctx, struct nc_udp_dispatch_context* udpDispatch)
{
    ctx->defaultUdpDispatch = udpDispatch;
}

void nc_rendezvous_remove_udp_dispatch(struct nc_rendezvous_context* ctx)
{
    ctx->defaultUdpDispatch = NULL;
}

void nc_rendezvous_packet_sent(const np_error_code ec, void* data)
{
    (void)ec;
    struct nc_rendezvous_context* ctx = (struct nc_rendezvous_context*)data;
    struct np_platform* pl = ctx->pl;
    pl->buf.free(ctx->sendBuffer);
    ctx->sendBuffer = NULL;
    nc_rendezvous_send_device_request(ctx);
}

void nc_rendezvous_send_device_request(struct nc_rendezvous_context* ctx)
{
    if (ctx->sendBuffer != NULL) {
        return;
    }

    if (ctx->packetIndex <= 0) {
        // There's no outstanding packets
        return;
    }

    struct np_platform* pl = ctx->pl;

    ctx->sendBuffer = pl->buf.allocate();
    if (ctx->sendBuffer == NULL) {
        NABTO_LOG_ERROR(LOG, "Cannot allocate buffer for sending rendezvous request");
        // since we cannot send packets just mark them all as "sent" and wait for a retransmission from somewhere else.
        ctx->packetIndex = 0;
        return;
    }

    ctx->packetIndex -= 1;
    struct nc_rendezvous_send_packet* packet = &ctx->packetList[ctx->packetIndex];

    uint8_t* start = ctx->pl->buf.start(ctx->sendBuffer);
    uint8_t* ptr = start;


    *ptr = NABTO_PROTOCOL_PREFIX_RENDEZVOUS;
    ptr++;
    memcpy(ptr, packet->connectionId, 14);
    ptr += 14;
    *ptr = packet->channelId;
    ptr++;

    *ptr = packet->type;
    ptr++;

    size_t used = ptr - start;
    nc_udp_dispatch_async_send_to(packet->udpDispatch, &packet->ep,
                                  start, (uint16_t)used, &ctx->sendCompletionEvent);

}

void nc_rendezvous_send_rendezvous(struct nc_rendezvous_context* ctx, struct nc_rendezvous_send_packet* packet)
{
    if (ctx->packetIndex >= NC_RENDEZVOUS_SEND_QUEUE_LENGTH) {
        // Queue is full, it's ok.
        return;
    }

    if (packet->udpDispatch == NULL) {

        if (!ctx->defaultUdpDispatch) {
            // No way to send packets
            return;
        }
        packet->udpDispatch = ctx->defaultUdpDispatch;
    }

    ctx->packetList[ctx->packetIndex] = *packet;
    ctx->packetIndex++;
    nc_rendezvous_send_device_request(ctx);
}

void nc_rendezvous_handle_packet(
    struct nc_rendezvous_context* ctx,
    struct nc_udp_dispatch_context* udpDispatch,
    struct nc_client_connection_dispatch_context* connectionDispatch,
    struct np_udp_endpoint* ep,
    uint8_t* buffer, uint16_t bufferSize)
{
    if (bufferSize < 17) {
        return;
    }
    uint8_t type = buffer[16];
    if (type == CT_RENDEZVOUS_CLIENT_REQUEST) {
        // validate connection id and make a CT_RENDEZVOUS_CLIENT_RESPONSE
        if (nc_client_connection_dispatch_validate_connection_id(connectionDispatch, buffer+1)) {
            struct nc_rendezvous_send_packet packet;
            packet.type = CT_RENDEZVOUS_CLIENT_RESPONSE;
            memcpy(packet.connectionId, buffer+1, 14);
            packet.channelId = buffer[15];
            packet.udpDispatch = udpDispatch;
            packet.ep = *ep;
            nc_rendezvous_send_rendezvous(ctx, &packet);
        }
    } else if (type == CT_RENDEZVOUS_PING_REQUEST) {
        struct nc_rendezvous_send_packet packet;
        packet.type = CT_RENDEZVOUS_PING_RESPONSE;
        memcpy(packet.connectionId, buffer+1, 14);
        packet.channelId = buffer[15];
        packet.udpDispatch = udpDispatch;
        packet.ep = *ep;
        nc_rendezvous_send_rendezvous(ctx, &packet);
    }
}
