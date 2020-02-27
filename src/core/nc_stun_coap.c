
#include "nc_stun_coap.h"

#include <platform/np_platform.h>
#include <core/nc_coap_server.h>
#include <core/nc_stun.h>
#include <core/nc_coap.h>
#include <platform/np_logging.h>
#include <core/nc_packet.h>

#include <cbor.h>

#define LOG NABTO_LOG_MODULE_COAP

void nc_rendezvous_handle_coap_p2p_stun(struct nabto_coap_server_request* request, void* data);
void nc_rendezvous_handle_coap_p2p_endpoints(struct nabto_coap_server_request* request, void* data);

np_error_code nc_stun_coap_init(struct nc_stun_coap_context* context, struct np_platform* platform, struct nc_coap_server_context* coap, struct nc_stun_context* stun)
{
    context->stun = stun;
    context->coap = coap;
    context->pl = platform;
    context->stunRequest = NULL;
    context->deinitialized = false;
    nabto_coap_error err = nabto_coap_server_add_resource(nc_coap_server_get_server(coap), NABTO_COAP_CODE_GET,
                                                          (const char*[]){"p2p", "endpoints", NULL},
                                                          &nc_rendezvous_handle_coap_p2p_endpoints, context,
                                                          &context->resource);
    if (err != NABTO_COAP_ERROR_OK) {
        nc_stun_coap_deinit(context);
        return nc_coap_error_to_core(err);
    }
    return NABTO_EC_OK;
}

void nc_stun_coap_deinit(struct nc_stun_coap_context* context)
{
    if (context->resource) {
        nabto_coap_server_remove_resource(context->resource);
        context->resource = NULL;
    }
    if (context->stunRequest) {
        nabto_coap_server_request_free(context->stunRequest);
        context->stunRequest = NULL;
    }
    context->deinitialized = true;
}
static void encode_ep(CborEncoder* encoder, const struct np_udp_endpoint* ep)
{
    CborEncoder map;
    if (ep->ip.type == NABTO_IPV4 || ep->ip.type == NABTO_IPV6) {
        cbor_encoder_create_map(encoder, &map, CborIndefiniteLength);

        cbor_encode_text_stringz(&map, "Ip");
        if (ep->ip.type == NABTO_IPV4) {
            cbor_encode_byte_string(&map, ep->ip.ip.v4, 4);
        } else {
            cbor_encode_byte_string(&map, ep->ip.ip.v6, 16);
        }
        cbor_encode_text_stringz(&map, "Port");
        cbor_encode_uint(&map, ep->port);
        cbor_encoder_close_container(encoder, &map);
    }
}

void nc_rendezvous_endpoints_completed(const np_error_code ec, const struct nabto_stun_result* res, void* data)
{
    struct nc_stun_coap_context* ctx = (struct nc_stun_coap_context*)data;
    uint8_t buffer[128];
    if (ctx->deinitialized) {
        // deinit will have freed the request
        return;
    }
    NABTO_LOG_TRACE(LOG, "Stun analysis completed with status: %s", np_error_code_to_string(ec));

    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Stun analysis failed with error: %s. Resolving rendezvous request with local endpoints only", np_error_code_to_string(ec));
    }

    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, 128, 0);

    CborEncoder array;
    cbor_encoder_create_array(&encoder, &array, CborIndefiniteLength);

    struct np_ip_address localAddrs[2];

    size_t addrs = ctx->pl->udp.get_local_ip(localAddrs, 2);

    for (size_t i = 0; i < addrs; i++) {
        struct np_udp_endpoint ep;
        ep.ip = localAddrs[i];
        uint16_t localPort = nc_stun_get_local_port(ctx->stun);
        ep.port = localPort;

        encode_ep(&array, &ep);
    }

    // encode the global ep if stun succeeded
    if (ec == NABTO_EC_OK) {
        struct np_udp_endpoint ep;
        nc_stun_convert_ep(&res->extEp, &ep);
        encode_ep(&array, &ep);
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
        nabto_coap_error err = nabto_coap_server_response_set_payload(request, buffer, used);
        if (err != NABTO_COAP_ERROR_OK) {
            // Dont try to add a payload on OOM it would propably fail
            nabto_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(5,00), NULL);
        } else {
            // On errors we should still cleanup the request
            nabto_coap_server_response_ready(request);
        }
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
    np_error_code ec = nc_stun_async_analyze(ctx->stun, true, &nc_rendezvous_endpoints_completed, ctx);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_INFO(LOG, "Failed to start stun analysis with: %s. Responing with local addresses only.", np_error_code_to_string(ec));
        nc_rendezvous_endpoints_completed(ec, NULL, ctx);
    }
}
