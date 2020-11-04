#include <nabto/nabto_device_experimental.h>
#include "nm_iam_coap_handler.h"

#include "../nm_iam.h"
#include "../nm_iam_user.h"
#include "../nm_iam_internal.h"

#include <stdlib.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_pairing_local_invite_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "pairing", "local-invite", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_POST, paths, &handle_request);

}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{

    struct nm_iam* iam = handler->iam;

    CborParser parser;
    CborValue value;

    if (!nm_iam_cbor_init_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    char* username = NULL;

    nm_iam_cbor_decode_kv_string(&value, "Username", &username);
    if (username == NULL || !nm_iam_user_validate_username(username)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes);
    nn_string_map_insert(&attributes, "IAM:Username", username);

    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
    if (!nm_iam_check_access(handler->iam, ref, "IAM:PairingLocalInvite", &attributes)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }
    nn_string_map_deinit(&attributes);

    struct nm_iam_user* user = nm_iam_find_user_by_username(iam, username);
    if (user == NULL) {
        nabto_device_coap_error_response(request, 404, "not found");
    } else {
        if (user->fingerprint != NULL) {
            // TODO
            nabto_device_coap_error_response(request, 400, "User is already paired");
        } else {

            char* fp;
            if (nabto_device_connection_get_client_fingerprint(iam->device, ref, &fp) != NABTO_DEVICE_EC_OK) {
                nabto_device_coap_error_response(request, 500, "Server error");
            } else {
                if (!nm_iam_user_set_fingerprint(user, fp)) {
                    nabto_device_coap_error_response(request, 500, "Insufficient resources");
                } else {
                    nm_iam_user_has_changed(iam, username);
                    nabto_device_coap_response_set_code(request, 201);
                    nabto_device_coap_response_ready(request);
                }
                nabto_device_string_free(fp);            
            }
        }
    }
}
