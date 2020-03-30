#include "nm_iam_coap_handler.h"
#include "nm_iam_user.h"
#include "nm_iam.h"

#include <stdlib.h>

#include <cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_remove_role_from_user_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "users", "{user}", "roles", "{role}",  NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_DELETE, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    const char* userId = nabto_device_coap_request_get_parameter(request, "user");
    const char* roleId = nabto_device_coap_request_get_parameter(request, "role");
    if (userId == NULL || roleId == NULL) {
        nabto_device_coap_error_response(request, 500, NULL);
        return;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes);
    nn_string_map_insert(&attributes, "IAM:UserId", userId);
    nn_string_map_insert(&attributes, "IAM:RoleId", roleId);

    if (!nm_iam_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:RemoveRoleFromUser", &attributes)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    nm_iam_remove_role_from_user(handler->iam, userId, roleId);

    nabto_device_coap_response_set_code(request, 202);
    nabto_device_coap_response_ready(request);
}
