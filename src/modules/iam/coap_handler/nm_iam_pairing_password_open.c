#include <nabto/nabto_device_experimental.h>
#include "nm_iam_coap_handler.h"

#include "../nm_iam.h"
#include "../nm_iam_user.h"
#include "../nm_iam_internal.h"

#include <stdlib.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_pairing_password_open_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "pairing", "password-open", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_POST, paths, &handle_request);

}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct nm_iam* iam = handler->iam;
    if (iam->state->passwordOpenPairing == false) {
        nabto_device_coap_error_response(request, 404, "Not Found");
        return;
    }
    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
    if (!nm_iam_check_access(handler->iam, ref, "IAM:PairingPasswordOpen", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    if (!nabto_device_connection_is_password_authenticated(handler->device, ref)) {
        nabto_device_coap_error_response(request, 401, "Access Denied");
        return;
    }

    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint(handler->device, ref, &fingerprint);
    if (ec) {
        nabto_device_coap_error_response(request, 500, "Server error");
        return;
    }

    CborParser parser;
    CborValue value;

    if (!nm_iam_cbor_init_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        free(fingerprint);
        return;
    }

    char* username = NULL;
    char* password = NULL;

    if (nm_iam_cbor_decode_kv_string(&value, "Password", &password)) {
        // If the user provides a password in the request the user
        // uses a 5.1 client. This is not suported any more.
        nabto_device_coap_error_response(request, 400, "5.1 clients are not supported for password pairing");
    } else {

        nm_iam_cbor_decode_kv_string(&value, "Username", &username);
        if (username == NULL || !nm_iam_user_validate_username(username)) {
            nabto_device_coap_error_response(request, 400, "Bad request");
        } else if (nm_iam_find_user(handler->iam, username) != NULL) {
            nabto_device_coap_error_response(request, 409, "Conflict");
        } else {
            if (!nm_iam_pair_new_client(handler->iam, request, username)) {
                nabto_device_coap_error_response(request, 500, "Server error");
            } else {
                // OK response
                nabto_device_coap_response_set_code(request, 201);
                nabto_device_coap_response_ready(request);
            }
        }
    }

    free(fingerprint);
    free(username);
    free(password);
}
