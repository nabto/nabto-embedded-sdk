#include "nc_rendezvous.h"

#include <core/nc_packet.h>
#include <core/nc_stun.h>
#include <core/nc_coap.h>
#include <core/nc_client_connect.h>

#include <platform/np_logging.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_RENDEZVOUS

void nc_rendezvous_send_stun_start_resp(struct nc_rendezvous_context* ctx);
void nc_rendezvous_send_stun_data_req(const np_error_code ec, const struct nabto_stun_result* res, void* data);
void nc_rendezvous_dtls_send_cb(const np_error_code ec, void* data);
void nc_rendezvous_handle_ctrl_req(struct nc_rendezvous_context* ctx,
                                   np_communication_buffer* buffer,
                                   uint16_t bufferSize);
void nc_rendezvous_send_device_request(struct nc_rendezvous_context* ctx);
void nc_rendezvous_send_dev_req_cb(const np_error_code ec, void* data);
void nc_rendezvous_handle_coap_p2p_stun(struct nabto_coap_server_request* request, void* userData);
void nc_rendezvous_handle_coap_p2p_rendezvous(struct nabto_coap_server_request* request, void* userData);


void nc_rendezvous_init(struct nc_rendezvous_context* ctx,
                        struct np_platform* pl,
                        struct nc_client_connection* conn,
                        struct np_dtls_srv_connection* dtls,
                        struct nc_stun_context* stun,
                        struct nc_coap_context* coap)
{
    memset(ctx, 0, sizeof(struct nc_rendezvous_context));
    ctx->pl = pl;
    ctx->conn = conn;
    ctx->dtls = dtls;
    ctx->stun = stun;
    ctx->coap = coap;

    ctx->priBuf = pl->buf.allocate();
    ctx->secBuf = pl->buf.allocate();
    ctx->epIndex = 0;
    ctx->sendingDevReqs = false;

    nabto_coap_server_add_resource(nc_coap_get_server(coap), NABTO_COAP_CODE_POST, "/p2p/stun",
                                   &nc_rendezvous_handle_coap_p2p_stun, ctx);
    nabto_coap_server_add_resource(nc_coap_get_server(coap), NABTO_COAP_CODE_POST, "/p2p/rendezvous",
                                   &nc_rendezvous_handle_coap_p2p_rendezvous, ctx);
    
}

void nc_rendezvous_destroy(struct nc_rendezvous_context* ctx)
{
    ctx->pl->buf.free(ctx->priBuf);
    ctx->pl->buf.free(ctx->secBuf);
}

void nc_rendezvous_handle_packet(struct nc_rendezvous_context* ctx,
                                 np_udp_endpoint ep,
                                 np_communication_buffer* buffer,
                                 uint16_t bufferSize)
{
    uint8_t* start = ctx->pl->buf.start(buffer);
    uint8_t ct = *(start+1);
    np_error_code ec;
    switch(ct) {
        case CT_RENDEZVOUS_CTRL_STUN_START_REQ:
        case CT_RENDEZVOUS_CTRL_STUN_START_RESP:
        case CT_RENDEZVOUS_CTRL_STUN_DATA_REQ:
        case CT_RENDEZVOUS_CTRL_STUN_DATA_RESP:
        case CT_RENDEZVOUS_CLIENT_RESPONSE:
        case CT_RENDEZVOUS_DEVICE_REQUEST:
            NABTO_LOG_ERROR(LOG, "Device should not receive rendezvouse contet type: %u", ct);
            break;
        case CT_RENDEZVOUS_CTRL_REQUEST:
            NABTO_LOG_INFO(LOG, "CTRL_REQUEST received");
            nc_rendezvous_handle_ctrl_req(ctx, buffer, bufferSize);
            break;
        case CT_RENDEZVOUS_CLIENT_REQUEST:
        {
            uint8_t* start = ctx->pl->buf.start(ctx->secBuf);
            uint8_t* ptr = start;
            np_error_code ec;
            NABTO_LOG_INFO(LOG, "RENDEZVOUS_CLIENT_REQUEST received");
            ctx->cliRespEp = ep;
            *ptr = AT_RENDEZVOUS;
            ptr++;
            *ptr = CT_RENDEZVOUS_CLIENT_RESPONSE;
            ec = nc_client_connect_async_send_to_ep(ctx->conn, &ctx->cliRespEp, ctx->priBuf, 2, &nc_rendezvous_send_dev_req_cb, ctx);
            if (ec != NABTO_EC_OK) {
                // TODO: handle_error
                NABTO_LOG_ERROR(LOG, "error sending CLIENT_RESPONSE, ignoring for now");
            }
            break;
        }
        default:
            NABTO_LOG_ERROR(LOG, "Invalid content type received");
            break;
    }
}


void nc_rendezvous_send_stun_start_resp(struct nc_rendezvous_context* ctx)
{
    uint8_t* start = ctx->pl->buf.start(ctx->priBuf);
    uint8_t* ptr = start;
    *ptr = AT_RENDEZVOUS_CONTROL;
    ptr++;
    *ptr = CT_RENDEZVOUS_CTRL_STUN_START_RESP;
    NABTO_LOG_INFO(LOG, "Sending CTRL_STUN_START_RESP");
    ctx->pl->dtlsS.async_send_to(ctx->pl, ctx->dtls, start, 2, &nc_rendezvous_dtls_send_cb, ctx);
}

void nc_rendezvous_dtls_send_cb(const np_error_code ec, void* data)
{
    if (ec != NABTO_EC_OK) {
        // No retransmissions for now
        NABTO_LOG_INFO(LOG, "DTLS send failed");
    }
}

void nc_rendezvous_stun_completed(const np_error_code ec, const struct nabto_stun_result* res, void* data)
{
    struct nc_rendezvous_context* ctx = (struct nc_rendezvous_context*)data;
    uint8_t* start = ctx->pl->buf.start(ctx->secBuf);
    uint8_t* ptr = start;
    NABTO_LOG_INFO(LOG, "Stun analysis completed with status: %s", np_error_code_to_string(ec));
    if (ec != NABTO_EC_OK) {
        // TODO: Handle error
        NABTO_LOG_ERROR(LOG, "Stun analysis failed, Ignoring errors for now");
        return;
    }
    if (res->extEp.addr.type == NABTO_STUN_IPV4) {
        struct np_udp_endpoint ep;
        NABTO_LOG_INFO(LOG, "External IP: %u.%u.%u.%u:%u", res->extEp.addr.v4.addr[0], res->extEp.addr.v4.addr[1], res->extEp.addr.v4.addr[2], res->extEp.addr.v4.addr[3], res->extEp.port);
        ep.port = res->extEp.port;
        memcpy(ep.ip.v4.addr, res->extEp.addr.v4.addr, 4);
        ep.ip.type = NABTO_IPV4;
        ptr = uint16_write_forward(ptr, EX_STUN_RESULT_IPV4);
        ptr = uint16_write_forward(ptr, 2);
        *ptr = res->mapping;
        ptr++;
        *ptr = res->filtering;
        ptr++;
        ptr = udp_ep_ext_write_forward(ptr, &ep);
    } else {
        NABTO_LOG_ERROR(LOG, "No IPV6 stun results yet");
        return;
    }

    // TODO: insert defect router extension
    
    struct nabto_coap_server_response* response = nabto_coap_server_create_response(ctx->stunRequest);
    nabto_coap_server_response_set_code(response, (nabto_coap_code)NABTO_COAP_CODE(2,05));
    nabto_coap_server_response_set_content_format(response, NABTO_COAP_CONTENT_FORMAT_APPLICATION_N5);
    nabto_coap_server_response_set_payload(response, start, ptr-start);
    nabto_coap_server_response_ready(response);
}

void nc_rendezvous_handle_ctrl_req(struct nc_rendezvous_context* ctx,
                                   np_communication_buffer* buffer,
                                   uint16_t bufferSize)
{
    uint8_t* start = ctx->pl->buf.start(buffer);
    uint8_t* ptr = start;
    ptr += 2; // Skip Application type and content type
    while (ptr < start+bufferSize-4) {
        if (uint16_read(ptr) == EX_UDP_IPV4_EP && ptr <= start+bufferSize-10) {// its IPV4 and theres space for IPV4 ext
            if (ctx->epIndex >= 10) {
                ptr += 10;
                NABTO_LOG_ERROR(LOG, "No room for more endpoints, ingnoring endpoint");
                continue;
            }
            ptr += 4; // skip extension header
            ctx->epList[ctx->epIndex].port = uint16_read(ptr);
            ptr += 2;
            ctx->epList[ctx->epIndex].ip.type = NABTO_IPV4;
            memcpy(ctx->epList[ctx->epIndex].ip.v4.addr, ptr, 4);
            ptr += 4;
            NABTO_LOG_INFO(LOG, "Received IP: %u.%u.%u.%u:%u", ctx->epList[ctx->epIndex].ip.v4.addr[0], ctx->epList[ctx->epIndex].ip.v4.addr[1], ctx->epList[ctx->epIndex].ip.v4.addr[2], ctx->epList[ctx->epIndex].ip.v4.addr[3], ctx->epList[ctx->epIndex].port);
            ctx->epIndex++;
        } else {
            // TODO: handle other extensions
            NABTO_LOG_ERROR(LOG, "CTRL_REQ should only have EX_UDP_IPV4_EP extensions for now");
        }
    }
    if (!ctx->sendingDevReqs) {
        nc_rendezvous_send_device_request(ctx);
    }
}


void nc_rendezvous_send_device_request(struct nc_rendezvous_context* ctx)
{
    uint8_t* start = ctx->pl->buf.start(ctx->priBuf);
    uint8_t* ptr = start;
    np_error_code ec;
    if (ctx->epIndex == 0) {
        ctx->sendingDevReqs = false;
        return;
    }
    ctx->epIndex -= 1;
    *ptr = AT_RENDEZVOUS;
    ptr++;
    *ptr = CT_RENDEZVOUS_DEVICE_REQUEST;
    NABTO_LOG_INFO(LOG, "Sending RENDEZVOUS_DEVICE_REQUEST");
    ec = nc_client_connect_async_send_to_ep(ctx->conn, &ctx->epList[ctx->epIndex], ctx->priBuf, 2, &nc_rendezvous_send_dev_req_cb, ctx);
    if (ec != NABTO_EC_OK) {
        // TODO: handle_error
        NABTO_LOG_ERROR(LOG, "error (%s) sending device request, trying next request", np_error_code_to_string(ec));
        nc_rendezvous_send_device_request(ctx);
    }
}

void nc_rendezvous_send_dev_req_cb(const np_error_code ec, void* data)
{
    if (ec != NABTO_EC_OK) {
        // TODO: handle error
        NABTO_LOG_ERROR(LOG, "Error sending device request, trying next request");
    }
    nc_rendezvous_send_device_request((struct nc_rendezvous_context*)data);
}

void nc_rendezvous_handle_coap_p2p_stun(struct nabto_coap_server_request* request, void* data)
{
    struct nc_rendezvous_context* ctx = (struct nc_rendezvous_context*)data;
    if (ctx->stunRequest != NULL) {
        NABTO_LOG_ERROR(LOG, "Received stun request while one is already active");
        struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
        nabto_coap_server_response_set_code(response, NABTO_COAP_CODE_PRECONDITION_FAILED);
        nabto_coap_server_response_ready(response);
        return;
    }
    ctx->stunRequest = request;
    np_error_code ec = nc_stun_async_analyze(ctx->stun, &nc_rendezvous_stun_completed, ctx);
    if (ec != NABTO_EC_OK) {
        // TODO: handle error
        NABTO_LOG_ERROR(LOG, "Failed to start stun analysis");
    }

}

void nc_rendezvous_handle_coap_p2p_rendezvous(struct nabto_coap_server_request* request, void* data)
{
    struct nc_rendezvous_context* ctx = (struct nc_rendezvous_context*)data;
    uint8_t* payload;
    size_t payloadLength;
    nabto_coap_server_request_get_payload(request, (void**)&payload, &payloadLength);
    NABTO_LOG_BUF(LOG, payload, payloadLength);
    uint8_t* ptr = payload;
    while (ptr < payload+payloadLength-4) {
        if (uint16_read(ptr) == EX_UDP_IPV4_EP && ptr <= payload+payloadLength-10) {// its IPV4 and theres space for IPV4 ext
            if (ctx->epIndex >= 10) {
                ptr += 10;
                NABTO_LOG_ERROR(LOG, "No room for more endpoints, ingnoring endpoint");
                continue;
            }
            ptr += 4; // skip extension header
            ctx->epList[ctx->epIndex].port = uint16_read(ptr);
            ptr += 2;
            ctx->epList[ctx->epIndex].ip.type = NABTO_IPV4;
            memcpy(ctx->epList[ctx->epIndex].ip.v4.addr, ptr, 4);
            ptr += 4;
            NABTO_LOG_INFO(LOG, "Received IP: %u.%u.%u.%u:%u", ctx->epList[ctx->epIndex].ip.v4.addr[0], ctx->epList[ctx->epIndex].ip.v4.addr[1], ctx->epList[ctx->epIndex].ip.v4.addr[2], ctx->epList[ctx->epIndex].ip.v4.addr[3], ctx->epList[ctx->epIndex].port);
            ctx->epIndex++;
        } else if (uint16_read(ptr) == EX_UDP_IPV6_EP && ptr <= payload+payloadLength-22) {// its IPV6 and theres space for IPV6 ext
            if (ctx->epIndex >= 10) {
                ptr += 22;
                NABTO_LOG_ERROR(LOG, "No room for more endpoints, ingnoring endpoint");
                continue;
            }
            ptr += 4; // skip extension header
            ctx->epList[ctx->epIndex].port = uint16_read(ptr);
            ptr += 2;
            ctx->epList[ctx->epIndex].ip.type = NABTO_IPV6;
            memcpy(ctx->epList[ctx->epIndex].ip.v6.addr, ptr, 16);
            ptr += 16;
            NABTO_LOG_INFO(LOG, "Received IPv6 endpoint for port %u", ctx->epList[ctx->epIndex].port);
            ctx->epIndex++;
        } else {
            // TODO: handle other extensions
            NABTO_LOG_ERROR(LOG, "CTRL_REQ should only have EX_UDP_IPV4_EP extensions for now, this was: %u", uint16_read(ptr));
            ptr += 2; // skip extension type
            uint16_t len = uint16_read(ptr);
            ptr += 2 + len;
            
        }
    }
    if (!ctx->sendingDevReqs) {
        nc_rendezvous_send_device_request(ctx);
    }
    struct nabto_coap_server_response* response = nabto_coap_server_create_response(request);
    nabto_coap_server_response_set_code(response, (nabto_coap_code)NABTO_COAP_CODE(2,04));
    nabto_coap_server_response_ready(response);
}
