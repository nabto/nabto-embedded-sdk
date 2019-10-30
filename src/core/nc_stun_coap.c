
#include "nc_stun_coap.h"

#include <platform/np_platform.h>
#include <core/nc_coap_server.h>
#include <core/nc_stun.h>
#include <platform/np_logging.h>
#include <core/nc_packet.h>
#include <core/nc_iam.h>

#include <cbor.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_rendezvous_handle_coap_p2p_stun(struct nabto_coap_server_request* request, void* data);
void nc_rendezvous_handle_coap_p2p_endpoints(struct nabto_coap_server_request* request, void* data);

void nc_stun_coap_init(struct nc_stun_coap_context* context, struct np_platform* platform, struct nc_coap_server_context* coap, struct nc_stun_context* stun)
{
    // TODO: make resource removable
    struct nabto_coap_server_resource* resource;
    context->stun = stun;
    context->coap = coap;
    context->pl = platform;
    context->stunRequest = NULL;
    // TODO: check if add fails
    nabto_coap_server_add_resource(nc_coap_server_get_server(coap), NABTO_COAP_CODE_GET,
                                   (const char*[]){"p2p", "endpoints", NULL},
                                   &nc_rendezvous_handle_coap_p2p_endpoints, context, &resource);
}

void nc_stun_coap_deinit(struct nc_stun_coap_context* context)
{
    // todo
}


void nc_rendezvous_endpoints_completed(const np_error_code ec, const struct nabto_stun_result* res, void* data)
{
    struct nc_stun_coap_context* ctx = (struct nc_stun_coap_context*)data;
    uint8_t buffer[128];
    NABTO_LOG_TRACE(LOG, "Stun analysis completed with status: %s", np_error_code_to_string(ec));

    // TODO: fix to use stun result. Here we get_local_ip and glues it with nc_stun_get_local_port to make endpoints
    if (ec != NABTO_EC_OK) {
        // TODO;

    }

    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, 128, 0);

    CborEncoder array;
    CborEncoder map;
    cbor_encoder_create_array(&encoder, &array, CborIndefiniteLength);

    struct np_ip_address localAddrs[2];

    size_t addrs = ctx->pl->udp.get_local_ip(localAddrs, 2);

    for (size_t i = 0; i < addrs; i++) {
        struct np_udp_endpoint ep;
        ep.ip = localAddrs[i];
        uint16_t localPort = nc_stun_get_local_port(ctx->stun);
        ep.port = localPort;

        cbor_encoder_create_map(&array, &map, CborIndefiniteLength);

        if (ep.ip.type == NABTO_IPV4 || ep.ip.type == NABTO_IPV6) {
            cbor_encode_text_stringz(&map, "Ip");
            if (ep.ip.type == NABTO_IPV4) {
                cbor_encode_byte_string(&map, ep.ip.ip.v4, 4);
            } else if (ep.ip.type == NABTO_IPV6) {
                cbor_encode_byte_string(&map, ep.ip.ip.v6, 16);
            }
            cbor_encode_text_stringz(&map, "Port");
            cbor_encode_uint(&map, ep.port);
        }
        cbor_encoder_close_container(&array, &map);
    }

    cbor_encoder_close_container(&encoder, &array);

    struct nabto_coap_server_request* request = ctx->stunRequest;
    if (cbor_encoder_get_extra_bytes_needed(&encoder) != 0) {
        // buffer was too small, this should not happen.
        nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(5,00), NULL);
    } else {
        size_t used = cbor_encoder_get_buffer_size(&encoder, buffer);
        nabto_coap_server_response_set_code(request, (nabto_coap_code)NABTO_COAP_CODE(2,05));
        nabto_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        // TODO: handle OOM
        nabto_coap_server_response_set_payload(request, buffer, used);
        // On errors we should still cleanup the request
        nabto_coap_server_response_ready(request);
    }
    nabto_coap_server_request_free(request);
    ctx->stunRequest = NULL;
}

void nc_rendezvous_handle_coap_p2p_endpoints(struct nabto_coap_server_request* request, void* data)
{
    struct nc_stun_coap_context* ctx = (struct nc_stun_coap_context*)data;

    if (ctx->stunRequest != NULL) {
        NABTO_LOG_ERROR(LOG, "Received stun request while one is already active");
        nabto_coap_server_response_set_code(request, NABTO_COAP_CODE_PRECONDITION_FAILED);
        // on errors we should still cleanup the request
        nabto_coap_server_response_ready(request);
        nabto_coap_server_request_free(request);
        return;
    }
    ctx->stunRequest = request;
    np_error_code ec = nc_stun_async_analyze(ctx->stun, &nc_rendezvous_endpoints_completed, ctx);
    if (ec != NABTO_EC_OK) {
        // TODO: handle error
        NABTO_LOG_ERROR(LOG, "Failed to start stun analysis");
    }
    nabto_coap_server_request_free(request);
}
