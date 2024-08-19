#include "nm_iam_coap_handler.h"
#include "../nm_iam_user.h"
#include "../nm_iam.h"
#include "../nm_iam_internal.h"

#include "../nm_iam_allocator.h"

#include <tinycbor/cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_get_me_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "me", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct nm_iam_user* user = nm_iam_internal_find_user_by_coap_request(handler->iam, request);

    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);


    if (!user && nabto_device_connection_is_password_authenticated(handler->iam->device, ref)) {
        char* username = NULL;
        NabtoDeviceError ec = nabto_device_connection_get_password_authentication_username(handler->iam->device, ref, &username);
        if (ec == NABTO_DEVICE_EC_OK) {
            user = nm_iam_internal_find_user_by_username(handler->iam, username);
        }
        nabto_device_string_free(username);
    }

    if (!user) {
        struct nm_iam_authorized_connection conn;
        NN_VECTOR_FOREACH(&conn, &handler->iam->authorizedConnections)
        {
            if (conn.ref == ref) {
                user = conn.user;
                break;
            }
        }
    }


    if (!user) {
        nabto_device_coap_error_response(request, 404, "Not paired");
    } else {
        size_t payloadSize = nm_iam_cbor_encode_user(user, NULL, 0);
        uint8_t* payload = nm_iam_calloc(1, payloadSize);
        if (payload == NULL) {
            return;
        }

        nm_iam_cbor_encode_user(user, payload, payloadSize);

        nabto_device_coap_response_set_code(request, 205);
        nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, payload, payloadSize);
        if (ec != NABTO_DEVICE_EC_OK) {
            nabto_device_coap_error_response(request, 500, "Insufficient resources");
        } else {
            nabto_device_coap_response_ready(request);
        }
        nm_iam_free(payload);
    }
}
