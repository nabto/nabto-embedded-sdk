#include "nm_iam_coap_handler.h"
#include "../nm_iam_user.h"
#include "../nm_iam_internal.h"
#include "../nm_iam.h"



#include <platform/np_allocator.h>

#include <cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_set_user_fingerprint_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "users", "{user}", "fingerprint",  NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_PUT, paths, &handle_request);
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

    char* fp = NULL;
    if (!nm_iam_cbor_decode_string(&value, &fp) || fp == NULL || strlen(fp) != 64) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes, np_allocator_get());
    nn_string_map_insert(&attributes, "IAM:Username", username);

    if (!nm_iam_internal_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:SetUserFingerprint", &attributes)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        np_free(fp);
        nn_string_map_deinit(&attributes);
        return;
    }
    nn_string_map_deinit(&attributes);

    if (nm_iam_internal_find_user_by_fingerprint(handler->iam, fp) != NULL) {
        nabto_device_coap_error_response(request, 409, "Conflict");
        np_free(fp);
        return;
    }
    struct nm_iam_user* user = nm_iam_internal_find_user(handler->iam, username);
    if (user == NULL) {
        nabto_device_coap_error_response(request, 404, NULL);
        np_free(fp);
        return;
    }
    if (!nm_iam_user_set_fingerprint(user, fp)) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        np_free(fp);
        return;
    }
    nm_iam_internal_state_has_changed(handler->iam);
    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
    np_free(fp);
}
