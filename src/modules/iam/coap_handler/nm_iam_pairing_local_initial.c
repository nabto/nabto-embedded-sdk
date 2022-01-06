#include <nabto/nabto_device_experimental.h>
#include "nm_iam_coap_handler.h"

#include "../nm_iam.h"
#include "../nm_iam_user.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_pairing.h"



static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_pairing_local_initial_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "pairing", "local-initial", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct nm_iam* iam = handler->iam;

    if (iam->state->localInitialPairing == false) {
        nabto_device_coap_error_response(request, 404, "Not Found");
        return;
    }

    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
    if (!nm_iam_internal_check_access(handler->iam, ref, "IAM:PairingLocalInitial", NULL) || !nabto_device_connection_is_local(handler->device, ref)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    const char* initialUserUsername = iam->state->initialPairingUsername;
    struct nm_iam_user* initialUser = nm_iam_internal_find_user_by_username(iam, initialUserUsername);
    if (initialUser == NULL) {
        nabto_device_coap_error_response(request, 404, "Not available");
    } else {
        if (nm_iam_pairing_is_user_paired(initialUser)) {
            // the initial user is already paired.
            nabto_device_coap_error_response(request, 409, "Already paired");
        } else {
            if (nm_iam_pairing_pair_user(iam, initialUser, ref)) {
                nm_iam_internal_state_has_changed(iam);
                nabto_device_coap_response_set_code(request, 201);
                nabto_device_coap_response_ready(request);
            } else {
                nabto_device_coap_error_response(request, 500, "Server error");
            }
        }
    }
}
