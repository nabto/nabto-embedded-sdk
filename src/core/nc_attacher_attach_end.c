#include "nc_attacher.h"

#include <core/nc_coap.h>

const char* attachEndPath[] = {"device", "attach-end"};

static void coap_attach_end_handler(struct nabto_coap_client_request* request, void* data);

np_error_code nc_attacher_attach_end_request(struct nc_attach_context* ctx, nc_attacher_attach_end_callback endCallback, void* userData)
{
    if (ctx->endCallback != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }

    struct nabto_coap_client_request* req;
    req = nabto_coap_client_request_new(nc_coap_client_get_client(ctx->coapClient),
                                        NABTO_COAP_METHOD_POST,
                                        2, attachEndPath,
                                        &coap_attach_end_handler,
                                        ctx, ctx->dtls);
    if (req == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    ctx->endCallback = endCallback;
    ctx->endCallbackUserData = userData;

    nabto_coap_client_request_send(req);
    return NABTO_EC_OPERATION_STARTED;
}

void coap_attach_end_handler(struct nabto_coap_client_request* request, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    nc_attacher_attach_end_callback cb = ctx->endCallback;
    void* userData = ctx->endCallbackUserData;
    np_error_code status = NABTO_EC_OK;

    struct nabto_coap_client_response* res = nabto_coap_client_request_get_response(request);
    if (!res) {
        status = NABTO_EC_UNKNOWN;
    } else {
        uint16_t resCode = nabto_coap_client_response_get_code(res);
        if (!nc_coap_is_status_ok(resCode)) {
            status = NABTO_EC_UNKNOWN;
        }
    }

    nabto_coap_client_request_free(request);
    ctx->endCallback = NULL;
    ctx->endCallbackUserData = NULL;
    cb(status, userData);
}
