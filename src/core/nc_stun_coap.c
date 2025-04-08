#include "nc_stun_coap.h"

#include <platform/np_platform.h>
#include <core/nc_coap_server.h>
#include <core/nc_stun.h>
#include <core/nc_coap.h>
#include <platform/np_logging.h>
#include <platform/np_local_ip_wrapper.h>
#include <platform/np_allocator.h>
#include <core/nc_packet.h>
#include <core/nc_cbor.h>

#include <tinycbor/cbor.h>


#define LOG NABTO_LOG_MODULE_COAP

#define ENDPOINTS_RESPONSE_ENDPOINTS_MAX 3
struct endpoints_response {
    struct np_udp_endpoint endpoints[ENDPOINTS_RESPONSE_ENDPOINTS_MAX];
    size_t endpointsSize;
};

void nc_rendezvous_handle_coap_p2p_endpoints(struct nc_coap_server_request* request, void* data);

static CborError encode_endpoints_response(CborEncoder* encoder, struct endpoints_response* endpointsResponse);

np_error_code nc_stun_coap_init(struct nc_stun_coap_context* context, struct np_platform* platform, struct nc_coap_server_context* coap, struct nc_stun_context* stun)
{
    context->stun = stun;
    context->coap = coap;
    context->pl = platform;
    nabto_coap_error err = nc_coap_server_add_resource(coap, NABTO_COAP_METHOD_GET,
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
        nc_coap_server_remove_resource(context->resource);
        context->resource = NULL;
    }
}

static CborError encode_ep(CborEncoder* encoder, const struct np_udp_endpoint* ep)
{
    CborEncoder map;
    if (ep->ip.type == NABTO_IPV4 || ep->ip.type == NABTO_IPV6) {
        NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encoder_create_map(encoder, &map, CborIndefiniteLength));
        NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_text_stringz(&map, "Ip"));
        if (ep->ip.type == NABTO_IPV4) {
            NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_byte_string(&map, ep->ip.ip.v4, 4));
        } else {
            NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_byte_string(&map, ep->ip.ip.v6, 16));
        }

        NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_text_stringz(&map, "Port"));
        NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_uint(&map, ep->port));
        return cbor_encoder_close_container(encoder, &map);
    }
    return CborNoError;
}

static CborError encode_endpoints_response(CborEncoder* encoder, struct endpoints_response* endpointsResponse)
{
    CborEncoder array;
    NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encoder_create_array(encoder, &array, CborIndefiniteLength));
    for (size_t i = 0; i < endpointsResponse->endpointsSize; i++) {
        struct np_udp_endpoint* ep = &endpointsResponse->endpoints[i];
        NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(encode_ep(&array, ep));
    }
    return cbor_encoder_close_container(encoder, &array);
}

static void send_500_response(struct nc_stun_coap_endpoints_request* ctx) {
    nc_coap_server_send_error_response(ctx->request, (nabto_coap_code)NABTO_COAP_CODE(5,00), NULL);
    nc_coap_server_request_free(ctx->request);
    np_free(ctx);
}

void nc_rendezvous_endpoints_completed(const np_error_code ec, const struct nabto_stun_result* res, void* data)
{
    struct nc_stun_coap_endpoints_request* ctx = (struct nc_stun_coap_endpoints_request*)data;
    struct np_platform* pl = ctx->stunCoap->pl;

    NABTO_LOG_TRACE(LOG, "Stun analysis completed with status: %s", np_error_code_to_string(ec));

    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Stun analysis failed with error: %s. Resolving rendezvous request with local endpoints only", np_error_code_to_string(ec));
    }

    struct endpoints_response endpointsResponse;
    memset(&endpointsResponse, 0, sizeof(struct endpoints_response));

    {
        // Get local addresses
        struct np_ip_address localAddrs[ENDPOINTS_RESPONSE_ENDPOINTS_MAX-1];
        size_t addrs = np_local_ip_get_local_ips(&pl->localIp, localAddrs, ENDPOINTS_RESPONSE_ENDPOINTS_MAX-1);
        uint16_t localPort = nc_stun_get_local_port(ctx->stunCoap->stun);
        for (size_t i = 0; i < addrs; i++) {
            struct np_udp_endpoint* ep = &endpointsResponse.endpoints[endpointsResponse.endpointsSize];
            ep->ip = localAddrs[i];
            ep->port = localPort;
            endpointsResponse.endpointsSize++;
        }
    }
    {
        // add the global ep if stun succeeded
        if (ec == NABTO_EC_OK) {
            nc_stun_convert_ep(&res->extEp, &endpointsResponse.endpoints[endpointsResponse.endpointsSize]);
            endpointsResponse.endpointsSize++;
        }
    }

    size_t bufferSize;
    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, NULL, 0, 0);
        if (encode_endpoints_response(&encoder, &endpointsResponse) != CborErrorOutOfMemory) {
            NABTO_LOG_ERROR(LOG, "Cannot determine size for endpoints response");
            send_500_response(ctx);
            return;
        }
        bufferSize = cbor_encoder_get_extra_bytes_needed(&encoder);
    }
    void* buffer = np_calloc(1, bufferSize);
    if (buffer == NULL) {
        NABTO_LOG_ERROR(LOG, "Cannot allocate memory for cbor object");
        send_500_response(ctx);
    }

    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, buffer, bufferSize, 0);
        if (encode_endpoints_response(&encoder, &endpointsResponse) != CborErrorOutOfMemory) {
            NABTO_LOG_ERROR(LOG, "Cannot encode endpoints as cbor");
            np_free(buffer);
            send_500_response(ctx);
            return;
        }
    }

    struct nc_coap_server_request* request = ctx->request;
        nc_coap_server_response_set_code(request, (nabto_coap_code)NABTO_COAP_CODE(2,05));
        nc_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        nabto_coap_error err = nc_coap_server_response_set_payload(request, buffer, bufferSize);
        if (err != NABTO_COAP_ERROR_OK) {
            // Dont try to add a payload on OOM it would propably fail
            nc_coap_server_send_error_response(request, (nabto_coap_code)NABTO_COAP_CODE(5,00), NULL);
        } else {
            // On errors we should still cleanup the request
            nc_coap_server_response_ready(request);
        }

    nc_coap_server_request_free(request);
    np_free(buffer);
    np_free(ctx);
}

void nc_rendezvous_handle_coap_p2p_endpoints(struct nc_coap_server_request* request, void* data)
{
    struct nc_stun_coap_context* stunCoap = (struct nc_stun_coap_context*)data;

    struct nc_stun_coap_endpoints_request* ctx = np_calloc(1, sizeof(struct nc_stun_coap_endpoints_request));
    if (ctx == NULL)  {
        nc_coap_server_send_error_response(request, NABTO_COAP_CODE_INTERNAL_SERVER_ERROR, "Out of memory");
        nc_coap_server_request_free(request);
    } else {
        ctx->request = request;
        ctx->stunCoap = stunCoap;
        np_error_code ec = nc_stun_async_analyze_simple(stunCoap->stun, &ctx->callback, &nc_rendezvous_endpoints_completed, ctx);
        if (ec != NABTO_EC_OK) {
            NABTO_LOG_INFO(LOG, "Failed to start stun analysis with: %s. Responing with local addresses only.", np_error_code_to_string(ec));
            nc_rendezvous_endpoints_completed(ec, NULL, ctx);
        }
    }
}
