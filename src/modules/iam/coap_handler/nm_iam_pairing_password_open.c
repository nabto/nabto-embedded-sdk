#include <nabto/nabto_device_experimental.h>

#include "../nm_iam.h"
#include "../nm_iam_allocator.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_user.h"
#include "nm_iam_coap_handler.h"

static void handle_request(struct nm_iam_coap_handler* handler,
                           NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_pairing_password_open_init(
    struct nm_iam_coap_handler* handler, NabtoDevice* device,
    struct nm_iam* iam)
{
    const char* paths[] = {"iam", "pairing", "password-open", NULL};
    return nm_iam_coap_handler_init(
        handler, device, iam, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler,
                    NabtoDeviceCoapRequest* request)
{
    struct nm_iam* iam = handler->iam;
    if (iam->state->passwordOpenPairing == false) {
        nabto_device_coap_error_response(request, 404, "Not Found");
        return;
    }
    NabtoDeviceConnectionRef ref =
        nabto_device_coap_request_get_connection_ref(request);
    if (!nm_iam_pairing_is_password_open_possible(handler->iam, ref)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    if (!nabto_device_connection_is_password_authenticated(handler->device,
                                                           ref)) {
        nabto_device_coap_error_response(request, 401, "Access Denied");
        return;
    }

    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint(handler->device, ref,
                                                        &fingerprint);
    if (ec) {
        nabto_device_coap_error_response(request, 500, "Server error");
        return;
    }

    CborParser parser;
    CborValue value;

    if (!nm_iam_cbor_init_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Invalid Cbor");
        nm_iam_free(fingerprint);
        return;
    }

    char* username = NULL;
    char* password = NULL;

    if (nm_iam_cbor_decode_kv_string(&value, "Password", &password)) {
        // If the user provides a password in the request the user
        // uses a 5.1 client. This is not suported any more.
        nabto_device_coap_error_response(
            request, 400, "5.1 clients are not supported for password pairing");
    } else {
        nm_iam_cbor_decode_kv_string(&value, "Username", &username);

        if (username == NULL) {
            nabto_device_coap_error_response(request, 400, "Username missing");
        } else {
            enum nm_iam_error e = nm_iam_internal_pair_new_client(handler->iam, username, fingerprint, NULL);
            switch (e) {
            case NM_IAM_ERROR_OK:
                // OK response
                nabto_device_coap_response_set_code(request, 201);
                nabto_device_coap_response_ready(request);
                break;
            case NM_IAM_ERROR_INVALID_ARGUMENT:
                nabto_device_coap_error_response(request, 400, "Invalid username");
                break;
            case NM_IAM_ERROR_USER_EXISTS:
                nabto_device_coap_error_response(request, 409, "Conflict");
                break;
            default:
                nabto_device_coap_error_response(request, 500, "Server error");
            }
        }
    }

    nm_iam_free(fingerprint);
    nm_iam_free(username);
    nm_iam_free(password);
}
