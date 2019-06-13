#include "nc_rendezvous.h"

#include <core/nc_packet.h>
#include <core/nc_client_connect.h>
#include <core/nc_udp_dispatch.h>


#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_RENDEZVOUS

void nc_rendezvous_send_device_request(struct nc_rendezvous_context* ctx);
void nc_rendezvous_send_dev_req_cb(const np_error_code ec, void* data);

void nc_rendezvous_init(struct nc_rendezvous_context* ctx,
                        struct np_platform* pl,
                        struct nc_udp_dispatch_context* udpDispatch)
{
    memset(ctx, 0, sizeof(struct nc_rendezvous_context));
    ctx->pl = pl;
    ctx->udpDispatch = udpDispatch;
    ctx->priBuf = pl->buf.allocate();
    ctx->packetIndex = 0;
    ctx->sendingDevReqs = false;
}

void nc_rendezvous_destroy(struct nc_rendezvous_context* ctx)
{

    ctx->pl->buf.free(ctx->priBuf);
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

    *ptr = AT_RENDEZVOUS;
    ptr++;
    *ptr = packet->type;

    ctx->sendingDevReqs = true;
    size_t used = ptr - start;
    nc_udp_dispatch_async_send_to(ctx->udpDispatch, &ctx->sendCtx, &packet->ep,
                                  ctx->priBuf, used,
                                  &nc_rendezvous_packet_sent, ctx);
}

void nc_rendezvous_send_dev_req_cb(const np_error_code ec, void* data)
{
    if (ec != NABTO_EC_OK) {
        // TODO: handle error
        NABTO_LOG_ERROR(LOG, "Error sending device request, trying next request");
    }
    nc_rendezvous_send_device_request((struct nc_rendezvous_context*)data);
}

void nc_rendezvous_send_rendezvous(struct nc_rendezvous_context* ctx, struct nc_rendezvous_send_packet* packet)
{
    if (ctx->packetIndex >= NC_RENDEZVOUS_SEND_QUEUE_LENGTH) {
        // todo log queue full
        return;
    }

    ctx->packetList[ctx->packetIndex] = *packet;
    ctx->packetIndex++;
    nc_rendezvous_send_device_request(ctx);
}
