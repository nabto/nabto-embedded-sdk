#include "nm_iam_pairing_password.h"

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_pairing_password_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "pairing", "password", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_POST, paths, &handle_request);

}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    if (!nm_iam_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "Pairing:Password", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint_full_hex(getDevice(), ref, &fingerprint);
    if (ec) {
        nabto_device_coap_error_response(request, 500, "Server error");
        return;
    }

    CborParser parser;
    CborValue value;

    std::string errorDescription;

    if (!nm_iam_cbor_init_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    char* password = NULL;
    char* name = NULL;

    if (!nm_iam_cbor_decode_string(value, &password) &&
        !nm_iam_cbor_decode_kv_string(value, "Password", &password))
    {
        // The password is required either as old or in the new format.
        nabto_device_coap_error_response(request, 400, "Missing password");
        return;
    }

    nm_iam_cbor_decode_kv_string(value, "Name", &name);

    if (strcmp(password, iam->pairingPassword) != 0) {
        nabto_device_coap_error_response(request, 401, "Wrong Password");
        return;
    }

    if (!nm_iam_pair_new_client(request, name)) {
        nabto_device_coap_error_response(request, 500, "Server error");
        return;
    }

    printf("Paired the user with the fingerprint %s\n", clientFingerprint);
    // OK response
    nabto_device_coap_response_set_code(request, 201);
    nabto_device_coap_response_ready(request);

    free(clientFingerprint);
    free(password);
    free(name);
}
