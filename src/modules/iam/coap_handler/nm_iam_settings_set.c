#include <nabto/nabto_device_experimental.h>
#include "nm_iam_coap_handler.h"

#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_pairing.h"



static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_settings_set_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "settings", "{key}", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_PUT, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct nm_iam* iam = handler->iam;
    NabtoDeviceConnectionRef conn = nabto_device_coap_request_get_connection_ref(request);
    if (!nm_iam_internal_check_access(handler->iam, conn , "IAM:SetSettings", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    CborParser parser;
    CborValue value;

    const char* key = nabto_device_coap_request_get_parameter(request, "key");
    if (key == NULL) {
        nabto_device_coap_error_response(request, 500, NULL);
        return;
    }

    enum nm_iam_cbor_error ec = nm_iam_cbor_init_parser(request, &parser, &value);
    if ( ec != IAM_CBOR_OK ) {
        nm_iam_cbor_send_error_response(request, ec);
        return;
    }

    if (strcmp(key, "password-open-pairing") == 0) {
        bool b = 0;
        if (!nm_iam_cbor_decode_bool(&value, &b)) {
            nabto_device_coap_error_response(request, 400, "Bad request");
            return;
        }

        nm_iam_state_set_password_open_pairing(iam->state, b);
        nm_iam_internal_state_has_changed(iam);

    } else if (strcmp(key, "password-invite-pairing") == 0) {
        bool b = 0;
        if (!nm_iam_cbor_decode_bool(&value, &b)) {
            nabto_device_coap_error_response(request, 400, "Bad request");
            return;
        }
        iam->state->passwordInvitePairing = b;
        nm_iam_internal_state_has_changed(iam);

    } else if (strcmp(key, "local-open-pairing") == 0) {
        bool b = 0;
        if (!nm_iam_cbor_decode_bool(&value, &b)) {
            nabto_device_coap_error_response(request, 400, "Bad request");
            return;
        }
        nm_iam_state_set_local_open_pairing(iam->state, b);
        nm_iam_internal_state_has_changed(iam);
    } else {
        nabto_device_coap_error_response(request, 404, "No such key");
        return;
    }

    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
}
