#include "nm_iam_coap_handler.h"
#include <nabto/nabto_device_experimental.h>

#include "../nm_iam.h"
#include "../nm_iam_allocator.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_user.h"

#include <tinycbor/cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_pairing_password_invite_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "pairing", "password-invite", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct nm_iam* iam = handler->iam;

    if (iam->state->passwordInvitePairing == false) {
        nabto_device_coap_error_response(request, 404, "Not Found");
        return;
    }

    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);

    if (!nm_iam_internal_check_access(handler->iam, ref, "IAM:PairingPasswordInvite", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    if (!nabto_device_connection_is_password_authenticated(handler->device, ref)) {
        nabto_device_coap_error_response(request, 401, "Access Denied");
        return;
    }

    char* username = NULL;

    if (nabto_device_connection_get_password_authentication_username(iam->device, ref, &username) != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 500, "Server error");
    } else {
        struct nm_iam_user* user = nm_iam_internal_find_user_by_username(iam, username);
        if (user == NULL) {
            nabto_device_coap_error_response(request, 500, "Server error");
        } else {
            char* fp = NULL;
            if (nabto_device_connection_get_client_fingerprint(iam->device, ref, &fp) != NABTO_DEVICE_EC_OK) {
                nabto_device_coap_error_response(request, 500, "Server error");
            } else {
                CborParser parser;
                CborValue value;

                struct nm_iam_user* fpUsr = nm_iam_internal_find_user_by_fingerprint(iam, fp);
                if (fpUsr != NULL) {
                    if (fpUsr == user) {
                        // Already paired
                        nabto_device_coap_response_set_code(request, 201);
                        nabto_device_coap_response_ready(request);
                    } else {
                        // Fingerprint in use
                        nabto_device_coap_response_set_code(request, 409);
                        nabto_device_coap_response_ready(request);
                    }
                } else {
                    char* fpName = NULL;
                    if (nm_iam_cbor_init_parser(request, &parser, &value) == IAM_CBOR_OK) {
                        nm_iam_cbor_decode_kv_string(&value, "FingerprintName", &fpName); // If decoding fails, leave fpName as NULL.
                    }
                    if (!nm_iam_user_add_fingerprint(user, fp, fpName)) {
                        nabto_device_coap_error_response(request, 500, "Insufficient resources");
                    } else {
                        nm_iam_user_set_password(user, NULL);
                        nm_iam_internal_state_has_changed(iam);
                        nabto_device_coap_response_set_code(request, 201);
                        nabto_device_coap_response_ready(request);
                    }
                    nm_iam_free(fpName);
                }
                nabto_device_string_free(fp);
            }
        }
        nabto_device_string_free(username);
    }
}
