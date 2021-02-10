#include "nc_attacher.h"
#include "nc_coap.h"
#include "nc_cbor.h"
#include <platform/np_error_code.h>
#include <platform/np_logging.h>
#include <coap/nabto_coap_client.h>

#include "cbor.h"

#define LOG NABTO_LOG_MODULE_ATTACHER

static void coap_handler(struct nabto_coap_client_request* request, void* data);

static size_t encode_request(struct nc_attacher_service_invoke_request* request, uint8_t* buffer, size_t bufferSize);
static bool parse_response(const uint8_t* buffer, size_t bufferSize, struct nc_attacher_service_invoke_response* response);

const char* serviceInvokePath[] = { "device", "service-invoke" };

np_error_code nc_attacher_service_invoke_execute(struct nc_attach_context *attacher, struct nc_attacher_service_invoke_context *serviceInvokeContext, nc_attacher_service_invoke_callback cb, void *userData)
{
    if (attacher->state != NC_ATTACHER_STATE_ATTACHED) {
        return NABTO_EC_NOT_ATTACHED;
    }

    serviceInvokeContext->coapRequest = nabto_coap_client_request_new(nc_coap_client_get_client(attacher->coapClient),
                                                              NABTO_COAP_METHOD_POST,
                                                              2, serviceInvokePath,
                                                              &coap_handler,
                                                              serviceInvokeContext, attacher->dtls);
    nabto_coap_client_request_set_content_format(serviceInvokeContext->coapRequest, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);

    size_t bufferSize = encode_request(&serviceInvokeContext->serviceInvokeRequest, NULL, 0);

    uint8_t* buffer = malloc(bufferSize);
    if (buffer == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    encode_request(&serviceInvokeContext->serviceInvokeRequest, buffer, bufferSize);

    nabto_coap_error err = nabto_coap_client_request_set_payload(serviceInvokeContext->coapRequest, buffer, bufferSize);
    free(buffer);
    if (err != NABTO_COAP_ERROR_OK) {
        return nc_coap_error_to_core(err);
    }

    serviceInvokeContext->cb = cb;
    serviceInvokeContext->cbData = userData;
    nabto_coap_client_request_send(serviceInvokeContext->coapRequest);
    return NABTO_EC_OK;
}

static void coap_handler(struct nabto_coap_client_request* request, void* data)
{
    struct nc_attacher_service_invoke_context* ctx = data;
    enum nabto_coap_client_status status =
        nabto_coap_client_request_get_status(request);
    np_error_code ec = NABTO_EC_OK;
    if (status == NABTO_COAP_CLIENT_STATUS_STOPPED) {
        ec = NABTO_EC_STOPPED;
    } else if (status == NABTO_COAP_CLIENT_STATUS_TIMEOUT) {
        ec = NABTO_EC_TIMEOUT;
    } else if (status != NABTO_COAP_CLIENT_STATUS_OK) {
        ec = NABTO_EC_UNKNOWN;
    } else {
        struct nabto_coap_client_response* res =
            nabto_coap_client_request_get_response(request);

        uint16_t resCode = nabto_coap_client_response_get_code(res);
        uint16_t contentFormat = 0;
        nabto_coap_client_response_get_content_format(res, &contentFormat);

        const uint8_t* payload = NULL;
        size_t payloadLength = 0;
        nabto_coap_client_response_get_payload(res, &payload, &payloadLength);

        if (resCode == 201 && contentFormat == NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR && payload != NULL) {
            if (parse_response(payload, payloadLength, &ctx->serviceInvokeResponse)) {
                ec = NABTO_EC_OK;
            } else {
                ec = NABTO_EC_BAD_RESPONSE;
            }

        } else {
            ec = NABTO_EC_BAD_RESPONSE;
        }
    }
    nabto_coap_client_request_free(request);

    ctx->cb(ec, ctx->cbData);
}

void nc_attacher_service_invoke_stop(struct nc_attacher_service_invoke_context* serviceInvokeContext)
{
    struct nabto_coap_client_request* req = serviceInvokeContext->coapRequest;
    if (req != NULL) {
        nabto_coap_client_request_cancel(req);
    }
}

size_t encode_request(struct nc_attacher_service_invoke_request* request, uint8_t* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "ServiceId");
    cbor_encode_text_stringz(&map, request->serviceId);

    cbor_encode_text_stringz(&map, "Message");
    cbor_encode_text_stringz(&map, request->message);

    cbor_encoder_close_container(&encoder, &map);

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}

bool parse_response(const uint8_t* buffer, size_t bufferSize, struct nc_attacher_service_invoke_response* response) {
    CborParser parser;
    CborValue map;
    CborValue statusCode;
    CborValue message;
    cbor_parser_init(buffer, bufferSize, 0, &parser, &map);
    if (!cbor_value_is_map(&map)) {
        return false;
    }
    cbor_value_map_find_value(&map, "StatusCode", &statusCode);
    cbor_value_map_find_value(&map, "Message", &message);

    if (!nc_cbor_copy_text_string(&message, &response->message, 4096)) {
        return false;
    }

    if (!cbor_value_is_integer(&statusCode)) {
        return false;
    }
    int tmp;
    if (cbor_value_get_int(&statusCode, &tmp) != CborNoError) {
        return false;
    }

    response->statusCode = (uint16_t)tmp;
    return true;
}
