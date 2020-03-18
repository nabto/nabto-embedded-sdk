#include "nm_iam_list_users.h"
#include "nm_iam_user.h"
#include "nm_iam.h"

#include <platform/np_vector.h>

#include <stdlib.h>

#include <cbor.h>

static void start_listen(struct nm_iam_list_users* handler);
static void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void handle_request(struct nm_iam_list_users* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_list_users_init(struct nm_iam_list_users* handler, NabtoDevice* device, struct nm_iam* iam)
{
    memset(handler, 0, sizeof(struct nm_iam_list_users));
    handler->device = device;
    handler->iam = iam;
    handler->listener = nabto_device_listener_new(device);
    handler->future = nabto_device_future_new(device);
    const char* paths[] = { "iam", "users", NULL };
    NabtoDeviceError status = nabto_device_coap_init_listener(device, handler->listener, NABTO_DEVICE_COAP_GET, paths);
    start_listen(handler);
    return status;
}

void nm_iam_list_users_deinit(struct nm_iam_list_users* handler)
{
    nabto_device_future_free(handler->future);
    nabto_device_listener_free(handler->listener);
}

void start_listen(struct nm_iam_list_users* handler)
{
    nabto_device_listener_new_coap_request(handler->listener, handler->future, &handler->request);
    nabto_device_future_set_callback(handler->future, &request_callback, handler);
}


void request_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    struct nm_iam_list_users* handler = userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    } else {
        handle_request(handler, handler->request);
        nabto_device_coap_request_free(handler->request);
        start_listen(handler);
    }
}

bool initCborParser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue)
{
    uint16_t contentFormat;
    NabtoDeviceError ec;
    ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        nabto_device_coap_error_response(request, 400, "Invalid Content Format");
        return false;
    }
    void* payload;
    size_t payloadSize;
    if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 400, "Missing payload");
        return false;
    }
    cbor_parser_init((const uint8_t*)payload, payloadSize, 0, parser, cborValue);
    return true;
}

static size_t encode_users(struct nm_iam_list_users* handler, void* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder array;
    cbor_encoder_create_array(&encoder, &array, CborIndefiniteLength);

    struct np_vector* users = &handler->iam->users;
    struct nm_iam_user* user;
    NP_VECTOR_FOREACH(user, users) {
        cbor_encode_text_stringz(&array, user->id);
    }

    cbor_encoder_close_container(&encoder, &array);

     return cbor_encoder_get_extra_bytes_needed(&encoder);
}

void handle_request(struct nm_iam_list_users* handler, NabtoDeviceCoapRequest* request)
{
    if (!nm_iam_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:ListUsers", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    size_t payloadSize = encode_users(handler, NULL, 0);
    uint8_t* payload = malloc(payloadSize);
    if (payload == NULL) {
        return;
    }

    encode_users(handler, payload, payloadSize);

    nabto_device_coap_response_set_code(request, 205);
    nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, payload, payloadSize);
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
    } else {
        nabto_device_coap_response_ready(request);
    }
    free(payload);
}
