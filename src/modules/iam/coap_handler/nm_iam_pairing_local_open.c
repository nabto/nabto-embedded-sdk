#include "nm_iam_coap_handler.h"
#include <nabto/nabto_device_experimental.h>

#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_user.h"

#include "../nm_iam_allocator.h"



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

    NabtoDeviceError ec = 0;
    char* fingerprint = NULL;
    ec = nabto_device_connection_get_client_fingerprint(handler->device, ref, &fingerprint);
    if (ec) {
        nabto_device_coap_error_response(request, 500, "Server error");
        return;
    }

    CborParser parser;
    CborValue value;

    enum nm_iam_cbor_error err = nm_iam_cbor_init_parser(request, &parser, &value);
    if ( err != IAM_CBOR_OK ) {
        nm_iam_cbor_send_error_response(request, err);
        nm_iam_free(fingerprint);
        return;
    }

    char* username = NULL;
    char* fpName = NULL;

    if (!nm_iam_cbor_decode_kv_string(&value, "Username", &username)) {
        nabto_device_coap_error_response(request, 400, "Invalid CBOR data for Username");
        nm_iam_free(fingerprint);
        return;
    }
    if (username == NULL) {
        nabto_device_coap_error_response(request, 400, "Username missing");
        nm_iam_free(fingerprint);
        return;
    }
    nm_iam_cbor_decode_kv_string(&value, "FingerprintName", &fpName); // FingerprintName is optional

    enum nm_iam_error e = nm_iam_internal_pair_new_client(handler->iam, username, fingerprint, fpName);
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

    nm_iam_free(fingerprint);
    nm_iam_free(fpName);
    nm_iam_free(username);
}
