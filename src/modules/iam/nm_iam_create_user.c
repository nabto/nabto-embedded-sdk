#include "nm_iam_coap_handler.h"
#include "nm_iam_user.h"
#include "nm_iam_internal.h"
#include "nm_iam.h"

#include <nn/vector.h>

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
    CborValue attributes;

    if (!nm_iam_cbor_init_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    char* fp = NULL;
    char* name = NULL;

    nm_iam_cbor_decode_kv_string(&value, "Fingerprint", &fp);
    if (fp == NULL) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    char* sct;
    NabtoDeviceError ec = nabto_device_create_server_connect_token(handler->iam->device, &sct);
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 500, "Server error");
        return;
    }

    char* nextId = nm_iam_make_user_id(handler->iam);
    struct nm_iam_user* user = nm_iam_user_new(nextId);
    free(nextId);

    nm_iam_cbor_decode_kv_string(&value, "Name", &name);

    nm_iam_user_set_fingerprint(user, fp);
    nm_iam_user_set_server_connect_token(user, sct);
    if (name != NULL) {
        nm_iam_user_set_name(user, name);
    }

    char* role = NULL;
    nm_iam_cbor_decode_kv_string(&value, "Role", &role);
    if (role == NULL) {
        // No role where provided, default to secondaryUserRole
        nm_iam_user_set_role(user, handler->iam->secondaryUserRole);
    }

    cbor_value_map_find_value(&value, "Attributes", &attributes);

    if (cbor_value_is_map(&attributes)) {
        // TODO: decode and add attributes
    }

    nm_iam_add_user(handler->iam, user);

    nabto_device_coap_response_set_code(request, 201);
    nabto_device_coap_response_ready(request);

    nabto_device_string_free(sct);
    free(fp);
    free(name);

}
