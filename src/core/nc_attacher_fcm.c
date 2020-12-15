#include "nc_attacher.h"
#include "nc_coap.h"
#include <platform/np_error_code.h>
#include <platform/np_logging.h>
#include <coap/nabto_coap_client.h>

#define LOG NABTO_LOG_MODULE_ATTACHER

static void coap_handler(struct nabto_coap_client_request* request, void* data);



np_error_code nc_attacher_fcm_send(struct nc_attach_context *attacher, struct nc_attacher_fcm_send_context *fcmContext, nc_attacher_fcm_send_callback cb, void *userData)
{
    if (attacher->state != NC_ATTACHER_STATE_ATTACHED) {
        return NABTO_EC_NOT_ATTACHED;
    }
    fcmContext->pathSegments[0] = "device";
    fcmContext->pathSegments[1] = "fcm";
    fcmContext->pathSegments[2] = fcmContext->fcmRequest.projectId;

    fcmContext->coapRequest = nabto_coap_client_request_new(nc_coap_client_get_client(attacher->coapClient),
                                                              NABTO_COAP_METHOD_POST,
                                                              3, fcmContext->pathSegments,
                                                              &coap_handler,
                                                              fcmContext, attacher->dtls);
    nabto_coap_client_request_set_content_format(fcmContext->coapRequest, NABTO_COAP_CONTENT_FORMAT_APPLICATION_JSON);
    nabto_coap_error err = nabto_coap_client_request_set_payload(fcmContext->coapRequest, fcmContext->fcmRequest.payload, strlen(fcmContext->fcmRequest.payload));
    if (err != NABTO_COAP_ERROR_OK) {
        return nc_coap_error_to_core(err);        
    }
    fcmContext->cb = cb;
    fcmContext->cbData = userData;
    nabto_coap_client_request_send(fcmContext->coapRequest);
    return NABTO_EC_OK;
}

// TODO: fix
static void coap_handler(struct nabto_coap_client_request* request, void* data)
{
    struct nc_attacher_fcm_send_context* ctx = data;
    enum nabto_coap_client_status status = nabto_coap_client_request_get_status(request);
    np_error_code ec = NABTO_EC_OK;
    if (status != NABTO_COAP_CLIENT_STATUS_OK) {
        ec = NABTO_EC_UNKNOWN;
    } else {
        struct nabto_coap_client_response* res = nabto_coap_client_request_get_response(request);

        uint16_t resCode = nabto_coap_client_response_get_code(res);

        if (resCode == 201) {
            ec = NABTO_EC_OK;
            // todo parse response
        } else {
            ec = NABTO_EC_UNKNOWN;
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
