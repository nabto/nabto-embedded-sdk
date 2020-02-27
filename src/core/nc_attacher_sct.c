#include "nc_attacher.h"

const char* sctUploadPath[2] = {"device", "sct"};

static void sct_request_handler(struct nabto_coap_client_request* request, void* data);

/**
 * return the number of bytes needed to encode the scts if an encoder
 * without a buffer is used. Else return 0.
 */
static size_t encode_scts(CborEncoder* encoder, struct np_vector* scts);

np_error_code nc_sct_upload(struct nc_attacher* attacher, nc_sct_callback cb)
{
    struct nc_attacher_sct_context* sctCtx = &attacher->sctContext;
    // TODO check for attaching state.
    if (attacher->state != NC_ATTACHER_STATE_ATTACHED) {
        return NABTO_EC_NO_OPERATION;
    }
    if (sctCtx->version == sctCtx->synchronizedVersion) {
        return NABTO_EC_NO_OPERATION;
    }
    if (sctCtx->coapRequest != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }

    size_t bufferSize;
    {
        CborEncoder encoder;
        cbor_encoder_init(&encoder, NULL, 0, 0);
        bufferSize = encode_scts(&encoder, &sctCtx->scts);
    }
    uint8_t* buffer = malloc(bufferSize);
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
                                        attacher, attacher->dtls);
    if (req == NULL) {
        free(buffer);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    np_error_code ec = NABTO_EC_OK;
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
    free(buffer);
    return ec;
}

void coap_request_handler(struct nabto_coap_client_request* request, void* userData)
{
    struct nnc_attacher_sct_context* sctCtx = userData;
    nc_sct_callback cb = sctCtx->callback;
    void* cbUserData = sctCtx->callbackUserData;
    np_error_code status;
    struct nabto_coap_client_response* res = nabto_coap_client_request_get_response(request);
    uint16_t resCode = nabto_coap_client_response_get_code(res);
    if (nc_coap_is_status_ok(resCode)) {
        status = NABTO_EC_OK;
        sctCtx->synchronizedVersion = sctCtx->uploadingVersion;
    } else {
        status = NABTO_EC_UNKNWON;
    }
    nabto_coap_client_request_free(request);
    sctCtx->callback = NULL;
    sctCtx->callbackUserData = NULL;
    cb(status, cbUserData);
}

size_t encode_scts(CborEncoder* encoder, struct np_vector* scts)
{
    size_t i;
    CborEncoder array;
    cbor_encoder_create_array(&encoder, &array, CborIndefiniteLength);

    size_t vectorSize = np_vector_size(scts);
    for (i = 0; i < vectorSize; i++) {
        char* str = np_vector_get(scts, i);
        cbor_encode_text_stringz(&array, str);
    }
    cbor_encoder_close_container(&encoder, &map);

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}
