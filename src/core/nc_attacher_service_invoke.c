#include "nc_attacher.h"
#include "nc_coap.h"
#include "nc_cbor.h"
#include "nc_coap_rest_error.h"
#include <platform/np_error_code.h>
#include <platform/np_logging.h>
#include <platform/np_allocator.h>
#include <nabto_coap/nabto_coap_client.h>

#include "tinycbor/cbor.h"

#define LOG NABTO_LOG_MODULE_ATTACHER

static void coap_handler(struct nabto_coap_client_request* request, void* data);

static CborError encode_request(CborEncoder* encoder, struct nc_attacher_service_invoke_request* request);
static bool parse_response(const uint8_t* buffer, size_t bufferSize, struct nc_attacher_service_invoke_response* response);

const char* serviceInvokePath[] = { "device", "service", "invoke" };

np_error_code nc_attacher_service_invoke_execute(struct nc_attach_context *attacher, struct nc_attacher_service_invoke_context *serviceInvokeContext, nc_attacher_service_invoke_callback cb, void *userData)
{
    if (attacher->state != NC_ATTACHER_STATE_ATTACHED) {
        return NABTO_EC_NOT_ATTACHED;
    }

    serviceInvokeContext->coapRequest = nabto_coap_client_request_new(nc_coap_client_get_client(attacher->coapClient),
                                                              NABTO_COAP_METHOD_POST,
                                                              3, serviceInvokePath,
                                                              &coap_handler,
                                                              serviceInvokeContext, attacher->dtls);
    nabto_coap_client_request_set_content_format(serviceInvokeContext->coapRequest, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);

    size_t bufferSize;
    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, NULL, 0, 0);
        if (encode_request(&encoder, &serviceInvokeContext->serviceInvokeRequest) != CborErrorOutOfMemory) {
            NABTO_LOG_ERROR(LOG, "Cannot determine the required size fot the service invocation request.");
            return NABTO_EC_FAILED;
        }
        bufferSize = cbor_encoder_get_extra_bytes_needed(&encoder);
    }

    uint8_t* buffer = np_calloc(1, bufferSize);
    if (buffer == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, buffer, bufferSize, 0);
        if (encode_request(&encoder, &serviceInvokeContext->serviceInvokeRequest) != CborNoError) {
            np_free(buffer);
            NABTO_LOG_ERROR(LOG, "Cannot encode service invocation request as cbor.");
            return NABTO_EC_FAILED;
        }
    }

    nabto_coap_error err = nabto_coap_client_request_set_payload(serviceInvokeContext->coapRequest, buffer, bufferSize);
    np_free(buffer);
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

        ec = NABTO_EC_UNKNOWN;
        if (resCode != 201) {
            struct nc_coap_rest_error error;
            nc_coap_rest_error_decode_response(res, &error);
            NABTO_LOG_ERROR(LOG, "Failed to invoke service. %s", error.message);
            nc_coap_rest_error_deinit(&error);
            ec = NABTO_EC_FAILED;
        } else if (contentFormat != NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
            NABTO_LOG_ERROR(LOG, "Unexpected content format");
            ec = NABTO_EC_BAD_RESPONSE;
        } else if (payload == NULL) {
            NABTO_LOG_ERROR(LOG, "Expected a payload in the response");
            ec = NABTO_EC_BAD_RESPONSE;
        } else {
            if (parse_response(payload, payloadLength, &ctx->serviceInvokeResponse)) {
                ec = NABTO_EC_OK;
            } else {
                NABTO_LOG_ERROR(LOG, "Could not parse cbor response from basestation");
                ec = NABTO_EC_BAD_RESPONSE;
            }
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

CborError encode_request(CborEncoder* encoder, struct nc_attacher_service_invoke_request* request)
{
    CborEncoder map;
    NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encoder_create_map(encoder, &map, CborIndefiniteLength));
    NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_text_stringz(&map, "ServiceId"));
    NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_text_stringz(&map, request->serviceId));
    NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_text_stringz(&map, "Message"));
    NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_byte_string(&map, request->message, request->messageLength));
    return cbor_encoder_close_container(encoder, &map);
}

bool parse_response(const uint8_t* buffer, size_t bufferSize, struct nc_attacher_service_invoke_response* response) {
    CborParser parser;
    CborValue map;
    CborError err;
    if (cbor_parser_init(buffer, bufferSize, 0, &parser, &map) != CborNoError ||
        !cbor_value_is_map(&map)) {
        NABTO_LOG_ERROR(LOG, "Invalid Cbor response");
        return false;
    }
    CborValue statusCode;
    CborValue message;
    CborValue messageFormat;
    int tmp;
    if (cbor_value_map_find_value(&map, "StatusCode", &statusCode) != CborNoError ||
        cbor_value_map_find_value(&map, "Message", &message) != CborNoError ||
        cbor_value_map_find_value(&map, "MessageFormat", &messageFormat) != CborNoError ||
        !cbor_value_is_integer(&statusCode) != CborNoError ||
        cbor_value_get_int(&statusCode, &tmp) != CborNoError) {
        NABTO_LOG_ERROR(LOG, "Parse Cbor response");
        return false;
    }

    if (tmp < 0 || tmp > UINT16_MAX) {
        NABTO_LOG_ERROR(LOG, "The status code is outside uint16_t range");
        return false;
    }

    response->statusCode = (uint16_t)tmp;

    // if messageFormat exists, use as intended. If not we assume the
    // basestation uses old format, and set messageFormat to BINARY
    if (cbor_value_is_integer(&messageFormat)) {
        err = cbor_value_get_int(&messageFormat, &tmp);
        if (err != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Failed to get integer from 'MessageFormat': %d", err);
            return false;
        }
        switch(tmp) {
            case NC_SERVICE_INVOKE_MESSAGE_FORMAT_BINARY:
            case NC_SERVICE_INVOKE_MESSAGE_FORMAT_NONE:
            case NC_SERVICE_INVOKE_MESSAGE_FORMAT_TEXT:
                response->messageFormat = (enum nc_attacher_service_invoke_message_format)tmp;
            break;
            default:
                NABTO_LOG_ERROR(LOG, "The received message format is not known.");
                return false;
        }

        if (response->messageFormat != NC_SERVICE_INVOKE_MESSAGE_FORMAT_NONE) {
            if (!nc_cbor_copy_byte_string(&message, &response->message,
                                      &response->messageLength, 65536)) {
                NABTO_LOG_ERROR(LOG, "Failed to copy message byte string");
                return false;
            }
        }
    } else {
        if (!nc_cbor_copy_byte_string(&message, &response->message,
                                         &response->messageLength, 65536)) {
            NABTO_LOG_ERROR(LOG, "Failed to copy message byte string (default binary)");
            return false;
        }
        response->messageFormat = NC_SERVICE_INVOKE_MESSAGE_FORMAT_BINARY;
    }

    return true;
}
