#include "nm_iam_coap_handler.h"
#include "../nm_iam_user.h"
#include "../nm_iam.h"
#include "../nm_iam_internal.h"

#include <stdlib.h>

#include <cbor.h>

const char* noti1 = "{\"message\": { \"notification\": { \"title\": \"Test notification\", \"body\": \"Notifications are working\" }, \"token\": \"";
const char* noti2 = "\" } }";

struct nm_iam_fcm_ctx {
    NabtoDeviceCoapRequest* req;
    NabtoDeviceFcmNotification* msg;
};


static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_send_fcm_test_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "fcm-push", "{user}", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_POST, paths, &handle_request);
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
        nabto_device_coap_error_response(ctx->req, 503, "Failed to send to basestation");
        nabto_device_fcm_notification_free(ctx->msg);
        nabto_device_coap_request_free(ctx->req);
        free(ctx);
        nabto_device_future_free(fut);
        return;
    }

    size_t payloadSize = encode_response(ctx, NULL, 0);
    uint8_t* payload = malloc(payloadSize);
    if (payload == NULL) {
        nabto_device_coap_error_response(ctx->req, 500, "Insufficient resources");
        nabto_device_fcm_notification_free(ctx->msg);
        nabto_device_coap_request_free(ctx->req);
        free(ctx);
        nabto_device_future_free(fut);
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
    free(payload);
    nabto_device_fcm_notification_free(ctx->msg);
    nabto_device_coap_request_free(ctx->req);
    free(ctx);
    nabto_device_future_free(fut);

}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    CborParser parser;
    CborValue value;
    const char* username = nabto_device_coap_request_get_parameter(request, "user");
    if (username == NULL || !nm_iam_cbor_init_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes);
    nn_string_map_insert(&attributes, "IAM:Username", username);

    if (!nm_iam_internal_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:SendFcmPush", &attributes)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        nn_string_map_deinit(&attributes);
        return;
    }
    nn_string_map_deinit(&attributes);

    struct nm_iam_user* user = nm_iam_internal_find_user(handler->iam, username);
    if (user == NULL) {
        nabto_device_coap_error_response(request, 404, "No such user");
        return;
    }

    if (user->fcmToken == NULL || user->fcmProjectId == NULL) {
        nabto_device_coap_error_response(request, 404, "User FCM config not found");
        return;
    }

    struct nm_iam_fcm_ctx* ctx;
    char* payload;

    if ((ctx = (struct nm_iam_fcm_ctx*)calloc(1, sizeof(struct nm_iam_fcm_ctx))) == NULL ||
        (payload = calloc(1, strlen(noti1) + strlen(noti2) + strlen(user->fcmToken))) == NULL ||
        (ctx->msg = nabto_device_fcm_notification_new(handler->iam->device)) == NULL)
    {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        free(ctx);
        free(payload);
        return;
    }

    ctx->req = request;

    NabtoDeviceFuture* fut = nabto_device_future_new(handler->iam->device);
    if (fut == NULL) {
        nabto_device_fcm_notification_free(ctx->msg);
        free(ctx);
        free(payload);
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
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
        free(payload);
        nabto_device_fcm_notification_free(ctx->msg);
        free(ctx);
        nabto_device_future_free(fut);
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        return;
    }
    free(payload);

    nabto_device_fcm_send(ctx->msg, fut);
    nabto_device_future_set_callback(fut, &msg_sent_callback, ctx);
}
