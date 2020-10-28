#include "nm_iam_coap_handler.h"
#include "../nm_iam_user.h"
#include "../nm_iam.h"

#include <stdlib.h>

#include <cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_set_user_sct_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "users", "{user}", "sct", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_PUT, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    CborParser parser;
    CborValue value;
    const char* userId = nabto_device_coap_request_get_parameter(request, "user");
    if (userId == NULL || !nm_iam_cbor_init_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    char* sct = NULL;
    if (!nm_iam_cbor_decode_string(&value, &sct) || sct == NULL) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes);
    nn_string_map_insert(&attributes, "IAM:UserId", userId);

    if (!nm_iam_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:SetUserSct", &attributes)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        nn_string_map_deinit(&attributes);
        free(sct);
        return;
    }
    nn_string_map_deinit(&attributes);

    struct nm_iam_user* user = nm_iam_find_user(handler->iam, userId);
    if (user == NULL) {
        nabto_device_coap_error_response(request, 404, NULL);
        free(sct);
        return;
    }
    if (!nm_iam_user_set_server_connect_token(user, sct)) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        free(sct);
        return;
    }
    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
    free(sct);
}
