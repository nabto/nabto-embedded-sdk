#include "nm_iam_coap_handler.h"
#include "../nm_iam_user.h"
#include "../nm_iam.h"
#include "../nm_iam_internal.h"

#include <stdlib.h>

#include <cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_set_user_password_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "users", "{user}", "password", NULL };
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

    char* pass = NULL;
    if (!nm_iam_cbor_decode_string(&value, &pass) || pass == NULL) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes);
    nn_string_map_insert(&attributes, "IAM:Username", username);

    if (!nm_iam_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:SetUserPassword", &attributes)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        nn_string_map_deinit(&attributes);
        free(pass);
        return;
    }
    nn_string_map_deinit(&attributes);

    struct nm_iam_user* user = nm_iam_find_user(handler->iam, username);
    if (user == NULL) {
        nabto_device_coap_error_response(request, 404, NULL);
        free(pass);
        return;
    }
    if (!nm_iam_user_set_password(user, pass)) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        free(pass);
        return;
    }
    nm_iam_user_has_changed(handler->iam, username);
    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
    free(pass);
}
