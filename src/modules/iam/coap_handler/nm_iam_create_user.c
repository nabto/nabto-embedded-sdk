#include "nm_iam_coap_handler.h"
#include "../nm_iam_user.h"
#include "../nm_iam_internal.h"
#include "../nm_iam.h"

#include <stdlib.h>

#include <cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_create_user_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "users", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
    if (!nm_iam_check_access(handler->iam, ref, "IAM:CreateUser", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    CborParser parser;
    CborValue value;

    if (!nm_iam_cbor_init_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    char* name = NULL;

    nm_iam_cbor_decode_kv_string(&value, "Name", &name);

    char* userName = nm_iam_make_user_name(handler->iam, name);
    free(name);

    char* userId = nm_iam_make_user_id(handler->iam);
    struct nm_iam_user* user = nm_iam_user_new(userId);
    free(userId);

    char* sct;
    if (nabto_device_create_server_connect_token(handler->iam->device, &sct) != NABTO_DEVICE_EC_OK ||
        !nm_iam_user_set_server_connect_token(user, sct) ||
        !nm_iam_user_set_name(user, userName) ||
        !nm_iam_user_set_role(user, handler->iam->conf->secondaryUserRole)) {

        nabto_device_coap_error_response(request, 500, "Server error");

        nabto_device_string_free(sct);
        free(userName);
        nm_iam_user_free(user);
        return;
    }
    nabto_device_string_free(sct);
    free(userName);

    nm_iam_add_user(handler->iam, user);

    size_t payloadSize = nm_iam_cbor_encode_user(user, NULL, 0);
    uint8_t* payload = malloc(payloadSize);
    if (payload == NULL) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        return;
    }

    nm_iam_cbor_encode_user(user, payload, payloadSize);

    nabto_device_coap_response_set_code(request, 201);
    nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, payload, payloadSize);
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
    } else {
        nabto_device_coap_response_ready(request);
    }
    free(payload);
}
