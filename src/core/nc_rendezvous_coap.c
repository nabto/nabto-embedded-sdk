#include "nc_rendezvous_coap.h"

#include <core/nc_coap_server.h>
#include <core/nc_packet.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_rendezvous_handle_coap_p2p_rendezvous(struct nabto_coap_server_request* request, void* data);

void nc_rendezvous_coap_init(struct nc_rendezvous_coap_context* context, struct nc_coap_server_context* coap, struct nc_rendezvous_context* rendezvous)
{
    context->coap = coap;
    context->rendezvous = rendezvous;
    nabto_coap_server_add_resource(nc_coap_server_get_server(coap), NABTO_COAP_CODE_POST, "/p2p/rendezvous",
                                   &nc_rendezvous_handle_coap_p2p_rendezvous, context);
}
void nc_rendezvous_handle_coap_p2p_rendezvous(struct nabto_coap_server_request* request, void* data)
{
    struct nc_rendezvous_coap_context* ctx = (struct nc_rendezvous_coap_context*)data;
    uint8_t* payload;
    size_t payloadLength;
    struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
    nabto_coap_server_request_get_payload(request, (void**)&payload, &payloadLength);
    NABTO_LOG_BUF(LOG, payload, payloadLength);
    if (payload == NULL) {
        nabto_coap_server_response_set_code(response, (nabto_coap_code)NABTO_COAP_CODE(4,00));
        nabto_coap_server_response_ready(response);
        return;
    }
    uint8_t* ptr = payload;
    uint8_t* end = payload+payloadLength;

    struct nc_rendezvous_send_packet packet;
    packet.type = CT_RENDEZVOUS_DEVICE_REQUEST;
    nc_coap_server_context_request_get_connection_id(ctx->coap, request, packet.connectionId);

    while (ptr+4 < end) {
        if (uint16_read(ptr) == EX_UDP_IPV4_EP && ptr+10 <= payload+payloadLength) {// its IPV4 and theres space for IPV4 ext
            ptr += 4; // skip extension header
            packet.ep.port = uint16_read(ptr);
            ptr += 2;
            packet.ep.ip.type = NABTO_IPV4;
            memcpy(packet.ep.ip.v4.addr, ptr, 4);
            ptr += 4;
            nc_rendezvous_send_rendezvous(ctx->rendezvous, &packet);
        } else if (uint16_read(ptr) == EX_UDP_IPV6_EP && ptr+22 <= payload+payloadLength) {// its IPV6 and theres space for IPV6 ext
            ptr += 4; // skip extension header
            packet.ep.port = uint16_read(ptr);
            ptr += 2;
            packet.ep.ip.type = NABTO_IPV6;
            memcpy(packet.ep.ip.v6.addr, ptr, 16);
            ptr += 16;
            nc_rendezvous_send_rendezvous(ctx->rendezvous, &packet);
        } else {
            // TODO: handle other extensions
            NABTO_LOG_ERROR(LOG, "CTRL_REQ should only have EX_UDP_IPV4_EP extensions for now, this was: %u", uint16_read(ptr));
            ptr += 2; // skip extension type
            uint16_t len = uint16_read(ptr);
            ptr += 2 + len;

        }
    }
    nabto_coap_server_response_set_code(response, (nabto_coap_code)NABTO_COAP_CODE(2,04));
    nabto_coap_server_response_ready(response);
}
