#include "nm_iam_coap_handler.h"
#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_user.h"



#include "../nm_iam_allocator.h"

#include <tinycbor/cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_set_user_fcm_token_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "users", "{user}", "fcm",  NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_PUT, paths, &handle_request);
}

bool handle_request_data(struct nm_iam* iam, CborValue* map, struct nm_iam_user* user)
{
    if (!cbor_value_is_map(map)) {
        return false;
    }

    char* t = NULL;
    char* p = NULL;

    CborValue token;
    CborValue projectId;
    cbor_value_map_find_value(map, "Token", &token);
    cbor_value_map_find_value(map, "ProjectId", &projectId);
    if (!nm_iam_cbor_decode_string(&token, &t)) {
         nm_iam_free(t);
         return false;
    }
    if (!nm_iam_cbor_decode_string(&projectId, &p)) {
         nm_iam_free(t);
         nm_iam_free(p);
         return false;
    }

    bool status = true;
    if (t != NULL && p != NULL && strlen(t) < iam->fcmTokenMaxLength && strlen(p) < iam->fcmProjectIdMaxLength) {
        nm_iam_user_set_fcm_token(user, t);
        nm_iam_user_set_fcm_project_id(user, p);
    } else {
        status = false;
    }
    nm_iam_free(t);
    nm_iam_free(p);
    return status;
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    CborParser parser;
    CborValue value;
    const char* username = nabto_device_coap_request_get_parameter(request, "user");
    if (username == NULL) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }
    enum nm_iam_cbor_error ec = nm_iam_cbor_init_parser(request, &parser, &value);
    if ( ec != IAM_CBOR_OK ) {
        nm_iam_cbor_send_error_response(request, ec);
        return;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes, nm_iam_allocator_get());
    nn_string_map_insert(&attributes, "IAM:Username", username);

    if (!nm_iam_internal_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:SetUserFcm", &attributes)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        nn_string_map_deinit(&attributes);
        return;
    }
    nn_string_map_deinit(&attributes);

    struct nm_iam_user* user = nm_iam_internal_find_user(handler->iam, username);
    if (user == NULL) {
        nabto_device_coap_error_response(request, 404, NULL);
    } else if (!handle_request_data(handler->iam, &value, user)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
    } else {
        nm_iam_internal_state_has_changed(handler->iam);
        nabto_device_coap_response_set_code(request, 204);
        nabto_device_coap_response_ready(request);
    }
}
