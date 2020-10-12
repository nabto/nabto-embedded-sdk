#include "nm_iam_coap_handler.h"
#include "nm_iam_user.h"
#include "nm_iam_internal.h"
#include "nm_iam.h"

#include <nn/vector.h>

#include <stdlib.h>

#include <cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_create_user_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "users", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
    if (!nm_iam_check_access(handler->iam, ref, "IAM:CreateUser", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    CborParser parser;
    CborValue value;
    CborValue roles;
    CborValue attributes;

    if (!nm_iam_cbor_init_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    char* fp = NULL;
    char* name = NULL;

    nm_iam_cbor_decode_kv_string(&value, "Fingerprint", &fp);
    if (fp == NULL) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    char* sct;
    NabtoDeviceError ec = nabto_device_create_server_connect_token(handler->iam->device, &sct);
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    char* nextId = nm_iam_next_user_id(handler->iam);
    struct nm_iam_user* user = nm_iam_user_new(nextId);
    free(nextId);

    nm_iam_cbor_decode_kv_string(&value, "Name", &name);

    nm_iam_user_set_fingerprint(user, fp);
    nm_iam_user_set_server_connect_token(user, sct);
    if (name != NULL) {
        nm_iam_user_set_name(user, name);
    }


    cbor_value_map_find_value(&value, "Roles", &roles);
    if (cbor_value_is_array(&roles)) {
        CborValue it;
        if (!cbor_value_enter_container(&roles, &it)) {
            free(fp); free(name);
            nabto_device_coap_error_response(request, 400, "Bad request");
            return;
        }
        while(!cbor_value_at_end(&it)) {
            char* role;
            if (!nm_iam_cbor_decode_string(&it, &role)) {
                free(fp); free(name);
                nabto_device_coap_error_response(request, 400, "Bad request");
                return;
            }
            nn_string_set_insert(&user->roles, role);
            free(role);
            if (cbor_value_advance_fixed(&it)) {
                free(fp); free(name);
                nabto_device_coap_error_response(request, 400, "Bad request");
                return;
            }
        }
        if (!cbor_value_leave_container(&roles, &it)) {
            free(fp); free(name);
            nabto_device_coap_error_response(request, 400, "Bad request");
            return;
        }
    } else {
        const char* roleStr;
        NN_STRING_SET_FOREACH(roleStr, &handler->iam->secondaryUserRoles) {
            nn_string_set_insert(&user->roles, roleStr);
        }
    }

    cbor_value_map_find_value(&value, "Attributes", &attributes);

    if (cbor_value_is_map(&attributes)) {
        // TODO: decode and add attributes
    }

    nm_iam_add_user(handler->iam, user);

    nabto_device_coap_response_set_code(request, 201);
    nabto_device_coap_response_ready(request);

    nabto_device_string_free(sct);
    free(fp);
    free(name);

}
