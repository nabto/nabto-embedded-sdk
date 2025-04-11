#include "nm_iam_coap_handler.h"
#include "../nm_iam_user.h"
#include "../nm_iam.h"
#include "../nm_iam_internal.h"

#include "../nm_iam_allocator.h"



#include <tinycbor/cbor.h>

static const char* LOGM = "iam";

static const char* noti1 = "{\"message\": { \"notification\": { \"title\": \"Test notification\", \"body\": \"Notifications are working\" }, \"token\": \"";
static const char* noti2 = "\" } }";

struct nm_iam_fcm_ctx {
    NabtoDeviceCoapRequest* req;
    NabtoDeviceFcmNotification* msg;
    struct nm_iam_coap_handler* handler;
};


static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_send_fcm_test_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "users", "{user}", "fcm-test", NULL };
    NabtoDeviceError ec = nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_POST, paths, &handle_request);
    nm_iam_coap_handler_set_async(handler, true);
    return ec;
}

size_t encode_response(struct nm_iam_fcm_ctx* ctx, void* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "StatusCode");
    cbor_encode_uint(&map, nabto_device_fcm_notification_get_response_status_code(ctx->msg));
    cbor_encode_text_stringz(&map, "Body");
    cbor_encode_text_stringz(&map, nabto_device_fcm_notification_get_response_body(ctx->msg));

    cbor_encoder_close_container(&encoder, &map);
    return cbor_encoder_get_extra_bytes_needed(&encoder);
}

void msg_sent_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
{
    struct nm_iam_fcm_ctx* ctx = (struct nm_iam_fcm_ctx*)data;
    if (ec != NABTO_DEVICE_EC_OK) {
        NN_LOG_ERROR(ctx->handler->iam->logger, LOGM, "FCM request failed. Basestation returned: %s", nabto_device_error_get_string(ec));
        nabto_device_coap_error_response(ctx->req, 503, "Failed to send to basestation");
        nabto_device_fcm_notification_free(ctx->msg);
        nm_iam_free(ctx);
        nabto_device_future_free(fut);
        nm_iam_coap_handler_async_request_end(ctx->handler);
        return;
    }

    size_t payloadSize = encode_response(ctx, NULL, 0);
    uint8_t* payload = nm_iam_calloc(1, payloadSize);
    if (payload == NULL) {
        nabto_device_coap_error_response(ctx->req, 500, "Insufficient resources");
        nabto_device_fcm_notification_free(ctx->msg);
        nm_iam_free(ctx);
        nabto_device_future_free(fut);
        nm_iam_coap_handler_async_request_end(ctx->handler);
        return;
    }

    encode_response(ctx, payload, payloadSize);

    nabto_device_coap_response_set_code(ctx->req, 201);
    nabto_device_coap_response_set_content_format(ctx->req, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    ec = nabto_device_coap_response_set_payload(ctx->req, payload, payloadSize);
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(ctx->req, 500, "Insufficient resources");
    } else {
        nabto_device_coap_response_ready(ctx->req);
    }
    nm_iam_free(payload);
    nabto_device_fcm_notification_free(ctx->msg);
    struct nm_iam_coap_handler* h = ctx->handler;
    nm_iam_free(ctx);
    nabto_device_future_free(fut);
    nm_iam_coap_handler_async_request_end(h);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    NN_LOG_INFO(handler->iam->logger, LOGM, "Handling fcm send request");
    const char* username = nabto_device_coap_request_get_parameter(request, "user");
    if (username == NULL) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        nm_iam_coap_handler_async_request_end(handler);
        return;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes, nm_iam_allocator_get());
    nn_string_map_insert(&attributes, "IAM:Username", username);

    if (!nm_iam_internal_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:SendUserFcmTest", &attributes)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        nn_string_map_deinit(&attributes);
        nm_iam_coap_handler_async_request_end(handler);
        return;
    }
    nn_string_map_deinit(&attributes);

    struct nm_iam_user* user = nm_iam_internal_find_user(handler->iam, username);
    if (user == NULL) {
        nabto_device_coap_error_response(request, 404, "No such user");
        nm_iam_coap_handler_async_request_end(handler);
        return;
    }

    if (user->fcmToken == NULL || user->fcmProjectId == NULL) {
        nabto_device_coap_error_response(request, 404, "User FCM config not found");
        nm_iam_coap_handler_async_request_end(handler);
        return;
    }

    struct nm_iam_fcm_ctx* ctx = NULL;
    char* payload = NULL;

    if ((ctx = (struct nm_iam_fcm_ctx*)nm_iam_calloc(1, sizeof(struct nm_iam_fcm_ctx))) == NULL ||
        (payload = nm_iam_calloc(1, strlen(noti1) + strlen(noti2) + strlen(user->fcmToken)+1)) == NULL ||
        (ctx->msg = nabto_device_fcm_notification_new(handler->iam->device)) == NULL)
    {
        NN_LOG_INFO(handler->iam->logger, LOGM, "failed to alloc. ctx: %p, payload: %p, ctx->msg: %p", ctx, payload, ctx?ctx->msg:NULL);
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        nm_iam_free(ctx);
        nm_iam_free(payload);
        nm_iam_coap_handler_async_request_end(handler);
        return;
    }

    ctx->req = request;
    ctx->handler = handler;

    NabtoDeviceFuture* fut = nabto_device_future_new(handler->iam->device);
    if (fut == NULL) {
        nabto_device_fcm_notification_free(ctx->msg);
        nm_iam_free(ctx);
        nm_iam_free(payload);
        NN_LOG_INFO(handler->iam->logger, LOGM, "failed to alloc future");
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        nm_iam_coap_handler_async_request_end(handler);
        return;
    }

    char* tmp = strcpy(payload, noti1);
    tmp += strlen(noti1);
    strcpy(tmp, user->fcmToken);
    tmp += strlen(user->fcmToken);
    strcpy(tmp, noti2);
    if (nabto_device_fcm_notification_set_payload(ctx->msg, payload) != NABTO_DEVICE_EC_OK ||
        nabto_device_fcm_notification_set_project_id(ctx->msg, user->fcmProjectId) != NABTO_DEVICE_EC_OK)
    {
        nm_iam_free(payload);
        nabto_device_fcm_notification_free(ctx->msg);
        nm_iam_free(ctx);
        nabto_device_future_free(fut);
        NN_LOG_INFO(handler->iam->logger, LOGM, "failed to set payload or project ID");
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        nm_iam_coap_handler_async_request_end(handler);
        return;
    }
    nm_iam_free(payload);

    nabto_device_fcm_send(ctx->msg, fut);
    nabto_device_future_set_callback(fut, &msg_sent_callback, ctx);
}
