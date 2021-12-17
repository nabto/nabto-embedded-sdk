#include <nabto/nabto_device_experimental.h>
#include "nm_iam_coap_handler.h"

#include "../nm_iam.h"
#include "../nm_iam_user.h"
#include "../nm_iam_internal.h"

#include <platform/np_heap.h>

#include <stdlib.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_pairing_local_open_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "pairing", "local-open", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct nm_iam* iam = handler->iam;

    if (iam->state->localOpenPairing == false) {
        nabto_device_coap_error_response(request, 404, "Not Found");
        return;
    }

    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
    if (!nm_iam_internal_check_access(handler->iam, ref, "IAM:PairingLocalOpen", NULL) || !nabto_device_connection_is_local(handler->device, ref)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
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
        return;
    }

    char* username = NULL;

    nm_iam_cbor_decode_kv_string(&value, "Username", &username);
    if (username == NULL || !nm_iam_user_validate_username(username) || strlen(username) > handler->iam->usernameMaxLength) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        np_free(username);
        return;
    }

    if (nm_iam_internal_find_user(handler->iam, username) != NULL) {
        nabto_device_coap_error_response(request, 409, "Conflict");
        np_free(fingerprint);
        np_free(username);
        return;
    }

    if (!nm_iam_internal_pair_new_client(handler->iam, request, username)) {
        nabto_device_coap_error_response(request, 500, "Server error");
        np_free(fingerprint);
        np_free(username);
        return;
    }

    // OK response
    nabto_device_coap_response_set_code(request, 201);
    nabto_device_coap_response_ready(request);

    np_free(fingerprint);
    np_free(username);
}
