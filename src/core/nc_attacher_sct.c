
#include "nc_attacher.h"

#include <core/nc_coap.h>
#include <platform/np_logging.h>
#include <platform/np_heap.h>

#include <cbor.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_ATTACHER

const char* sctUploadPath[2] = {"device", "sct"};

static void sct_request_handler(struct nabto_coap_client_request* request, void* data);

/**
 * return the number of bytes needed to encode the scts if an encoder
 * without a buffer is used. Else return 0.
 */
static size_t encode_scts(CborEncoder* encoder, struct nn_string_set* scts);

np_error_code nc_attacher_sct_upload(struct nc_attach_context* attacher, nc_attacher_sct_callback cb, void* userData)
{
    struct nc_attacher_sct_context* sctCtx = &attacher->sctContext;
    if (sctCtx->version == sctCtx->synchronizedVersion) {
        NABTO_LOG_TRACE(LOG, "SCT already synchronized no operation");
        return NABTO_EC_NO_OPERATION;
    }
    if (sctCtx->callback != NULL) {
        NABTO_LOG_TRACE(LOG, "SCT operation in progress");
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }

    size_t bufferSize;
    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, NULL, 0, 0);
        bufferSize = encode_scts(&encoder, &sctCtx->scts);
    }
    uint8_t* buffer = np_calloc(1, bufferSize);
    if (!buffer) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, buffer, bufferSize, 0);
        encode_scts(&encoder, &sctCtx->scts);
    }

    struct nabto_coap_client_request* req;
    req = nabto_coap_client_request_new(nc_coap_client_get_client(attacher->coapClient),
                                        NABTO_COAP_METHOD_PUT,
                                        2, sctUploadPath,
                                        &sct_request_handler,
                                        &attacher->sctContext, attacher->dtls);
    if (req == NULL) {
        np_free(buffer);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    np_error_code ec = NABTO_EC_OPERATION_STARTED;
    nabto_coap_client_request_set_content_format(req, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_coap_error err = nabto_coap_client_request_set_payload(req, buffer, bufferSize);
    if (err != NABTO_COAP_ERROR_OK) {
        nabto_coap_client_request_free(req);
        ec = nc_coap_error_to_core(err);
    } else {
        sctCtx->callback = cb;
        sctCtx->callbackUserData = userData;
        sctCtx->uploadingVersion = sctCtx->version;
        nabto_coap_client_request_send(req);
    }
    np_free(buffer);
    return ec;
}

void sct_request_handler(struct nabto_coap_client_request* request, void* userData)
{
    struct nc_attacher_sct_context* sctCtx = userData;
    nc_attacher_sct_callback cb = sctCtx->callback;
    void* cbUserData = sctCtx->callbackUserData;
    np_error_code status;
    struct nabto_coap_client_response* res = nabto_coap_client_request_get_response(request);
    uint16_t resCode = nabto_coap_client_response_get_code(res);
    if (nc_coap_is_status_ok(resCode)) {
        status = NABTO_EC_OK;
        sctCtx->synchronizedVersion = sctCtx->uploadingVersion;
        NABTO_LOG_TRACE(LOG, "SCT version %u successfully uploaded", sctCtx->synchronizedVersion);
    } else {
        NABTO_LOG_TRACE(LOG, "SCT uploaded failed: %u", resCode);
        status = NABTO_EC_UNKNOWN;
    }
    nabto_coap_client_request_free(request);
    sctCtx->callback = NULL;
    sctCtx->callbackUserData = NULL;
    cb(status, cbUserData);
}

size_t encode_scts(CborEncoder* encoder, struct nn_string_set* scts)
{
    CborEncoder array;
    cbor_encoder_create_array(encoder, &array, CborIndefiniteLength);

    const char* str;
    NN_STRING_SET_FOREACH(str, scts) {
        cbor_encode_text_stringz(&array, str);
    }
    cbor_encoder_close_container(encoder, &array);

    return cbor_encoder_get_extra_bytes_needed(encoder);
}
