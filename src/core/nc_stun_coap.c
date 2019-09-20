
#include "nc_stun_coap.h"

#include <platform/np_platform.h>
#include <core/nc_coap_server.h>
#include <core/nc_stun.h>
#include <platform/np_logging.h>
#include <core/nc_packet.h>
#include <core/nc_iam.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_rendezvous_handle_coap_p2p_stun(struct nabto_coap_server_request* request, void* data);

void nc_stun_coap_init(struct nc_stun_coap_context* context, struct np_platform* platform, struct nc_coap_server_context* coap, struct nc_stun_context* stun)
{
    context->stun = stun;
    context->coap = coap;
    context->pl = platform;
    context->stunRequest = NULL;
    nabto_coap_server_add_resource(nc_coap_server_get_server(coap), NABTO_COAP_CODE_POST,
                                   (const char*[]){"p2p", "stun", NULL},
                                   &nc_rendezvous_handle_coap_p2p_stun, context);
}

void nc_stun_coap_deinit(struct nc_stun_coap_context* context)
{
    // todo
}


void nc_rendezvous_stun_completed(const np_error_code ec, const struct nabto_stun_result* res, void* data)
{
    struct nc_stun_coap_context* ctx = (struct nc_stun_coap_context*)data;
    uint8_t buffer[128];
    uint8_t* start = buffer;
    uint8_t* ptr = start;
    NABTO_LOG_INFO(LOG, "Stun analysis completed with status: %s", np_error_code_to_string(ec));

    struct nabto_coap_server_response* response = nabto_coap_server_create_response(ctx->stunRequest);

    if (ec == NABTO_EC_OK) {
        // Write ipv4 nat mapping and filtering
        ptr = uint16_write_forward(ptr, EX_STUN_RESULT_IPV4);
        ptr = uint16_write_forward(ptr, 2);
        *ptr = res->mapping;
        ptr++;
        *ptr = res->filtering;
        ptr++;

        // write public ip address
        if (res->extEp.addr.type == NABTO_STUN_IPV4) {
            struct np_udp_endpoint ep;
            ep.port = res->extEp.port;
            memcpy(ep.ip.ip.v4, res->extEp.addr.v4.addr, 4);
            ep.ip.type = NABTO_IPV4;
            ptr = udp_ep_ext_write_forward(ptr, &ep);
        }

        // TODO: insert defect router extension
    }
    // write local ips
    struct np_ip_address localAddrs[2];

    size_t addrs = ctx->pl->udp.get_local_ip(localAddrs, 2);

    for (size_t i = 0; i < addrs; i++) {
        struct np_udp_endpoint ep;
        ep.ip = localAddrs[i];
        uint16_t localPort = nc_stun_get_local_port(ctx->stun);
        ep.port = localPort;
        ptr = udp_ep_ext_write_forward(ptr, &ep);
    }

    nabto_coap_server_response_set_code(response, (nabto_coap_code)NABTO_COAP_CODE(2,05));
    nabto_coap_server_response_set_content_format(response, NABTO_COAP_CONTENT_FORMAT_APPLICATION_N5);
    nabto_coap_server_response_set_payload(response, start, ptr-start);

    nabto_coap_server_response_ready(response);
    ctx->stunRequest = NULL;
}

void nc_rendezvous_handle_coap_p2p_stun(struct nabto_coap_server_request* request, void* data)
{
    struct nc_stun_coap_context* ctx = (struct nc_stun_coap_context*)data;

    struct nc_client_connection* connection = nabto_coap_server_request_get_connection(request);

    if (connection == NULL || nc_iam_check_access(connection, "P2P:Stun", NULL, 0) != NABTO_EC_OK) {
        nabto_coap_server_create_error_response(request, NABTO_COAP_CODE_FORBIDDEN, "Access denied");
        return;
    }

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
