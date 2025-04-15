#include "nc_attacher.h"
#include "nc_cbor.h"
#include "nc_coap.h"
#include <nabto_coap/nabto_coap_client.h>
#include <platform/np_allocator.h>
#include <platform/np_error_code.h>
#include <platform/np_logging.h>


#include "tinycbor/cbor.h"

#define LOG NABTO_LOG_MODULE_ATTACHER

static void coap_handler(struct nabto_coap_client_request* request, void* data);

static CborError encode_request(CborEncoder* encoder, struct nc_attacher_fcm_request* request);
static bool parse_response(const uint8_t* buffer, size_t bufferSize, struct nc_attacher_fcm_response* response);

const char* sendPath[] = { "device", "fcm", "send" };

np_error_code nc_attacher_fcm_send(struct nc_attach_context *attacher, struct nc_attacher_fcm_send_context *fcmContext, nc_attacher_fcm_send_callback cb, void *userData)
{
    if (attacher->state != NC_ATTACHER_STATE_ATTACHED) {
        return NABTO_EC_NOT_ATTACHED;
    }

    fcmContext->coapRequest = nabto_coap_client_request_new(nc_coap_client_get_client(attacher->coapClient),
                                                              NABTO_COAP_METHOD_POST,
                                                              3, sendPath,
                                                              &coap_handler,
                                                              fcmContext, attacher->dtls);
    nabto_coap_client_request_set_content_format(fcmContext->coapRequest, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);

    size_t bufferSize = 0;
    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, NULL, 0, 0);
        if (encode_request(&encoder, &fcmContext->fcmRequest) != CborErrorOutOfMemory) {
            NABTO_LOG_ERROR(LOG, "Cannot determine buffersize for fcm cbor request");
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
        if (encode_request(&encoder, &fcmContext->fcmRequest) != CborNoError) {
            NABTO_LOG_ERROR(LOG, "Cannot encode fcm request as cbor");
            np_free(buffer);
            return NABTO_EC_FAILED;
        }
    }

    nabto_coap_error err = nabto_coap_client_request_set_payload(fcmContext->coapRequest, buffer, bufferSize);
    np_free(buffer);
    if (err != NABTO_COAP_ERROR_OK) {
        return nc_coap_error_to_core(err);
    }

    fcmContext->cb = cb;
    fcmContext->cbData = userData;
    nabto_coap_client_request_send(fcmContext->coapRequest);
    return NABTO_EC_OK;
}

static void coap_handler(struct nabto_coap_client_request* request, void* data)
{
    struct nc_attacher_fcm_send_context* ctx = data;
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
            if (parse_response(payload, payloadLength, &ctx->fcmResponse)) {
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

void nc_attacher_fcm_send_stop(struct nc_attacher_fcm_send_context* fcmSend)
{
    struct nabto_coap_client_request* req = fcmSend->coapRequest;
    if (req != NULL) {
        nabto_coap_client_request_cancel(req);
    }
}

CborError encode_request(CborEncoder* encoder, struct nc_attacher_fcm_request* request)
{
    CborEncoder map;
    NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encoder_create_map(encoder, &map, CborIndefiniteLength));

    NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_text_stringz(&map, "ProjectId"));
    NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_text_stringz(&map, request->projectId));

    NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_text_stringz(&map, "Body"));
    NC_CBOR_CHECK_FOR_ERROR_EXCEPT_OOM(cbor_encode_text_stringz(&map, request->payload));

    return cbor_encoder_close_container(encoder, &map);
}

bool parse_response(const uint8_t* buffer, size_t bufferSize, struct nc_attacher_fcm_response* response) {
    CborParser parser;
    CborValue map;
    CborValue statusCode;
    CborValue body;
    if (cbor_parser_init(buffer, bufferSize, 0, &parser, &map) != CborNoError) {
        return false;
    }
    if (!cbor_value_is_map(&map)) {
        return false;
    }
    if (cbor_value_map_find_value(&map, "StatusCode", &statusCode) != CborNoError) {
        return false;
    }
    if (cbor_value_map_find_value(&map, "Body", &body) != CborNoError) {
        return false;
    }

    if (!nc_cbor_copy_text_string(&body, &response->body, 4096)) {
        return false;
    }

    if (!cbor_value_is_integer(&statusCode)) {
        return false;
    }
    int tmp = 0;
    if (cbor_value_get_int(&statusCode, &tmp) != CborNoError) {
        return false;
    }

    if (tmp > UINT16_MAX || tmp < 0) {
        return false;
    }

    response->statusCode = (uint16_t)tmp;
    return true;
}
