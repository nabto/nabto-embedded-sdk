#include "nm_iam_coap_handler.h"
#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_user.h"



#include "../nm_iam_allocator.h"

#include <tinycbor/cbor.h>

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
    const char* username = nabto_device_coap_request_get_parameter(request, "user");
    if (username == NULL) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }
    enum nm_iam_cbor_error ec = nm_iam_cbor_init_parser(request, &parser, &value);
    if ( ec != IAM_CBOR_OK ) {
        nm_iam_cbor_send_error_response(request, ec);
        return;
    }

    char* sct = NULL;
    if (!nm_iam_cbor_decode_string(&value, &sct) || sct == NULL || strlen(sct) > handler->iam->sctMaxLength) {
        nabto_device_coap_error_response(request, 400, "Invalid SCT");
        nm_iam_free(sct);
        return;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes, nm_iam_allocator_get());
    nn_string_map_insert(&attributes, "IAM:Username", username);

    if (!nm_iam_internal_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:SetUserSct", &attributes)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        nn_string_map_deinit(&attributes);
        nm_iam_free(sct);
        return;
    }
    nn_string_map_deinit(&attributes);

    struct nm_iam_user* user = nm_iam_internal_find_user(handler->iam, username);
    if (user == NULL) {
        nabto_device_coap_error_response(request, 404, NULL);
        nm_iam_free(sct);
        return;
    }
    if (!nm_iam_user_set_sct(user, sct)) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        nm_iam_free(sct);
        return;
    }
    nm_iam_internal_state_has_changed(handler->iam);
    // TODO this can return OOM
    nabto_device_add_server_connect_token(handler->iam->device, sct);
    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
    nm_iam_free(sct);
}
