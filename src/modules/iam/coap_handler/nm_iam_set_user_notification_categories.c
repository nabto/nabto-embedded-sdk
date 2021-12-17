#include "nm_iam_coap_handler.h"
#include "../nm_iam_user.h"
#include "../nm_iam_internal.h"
#include "../nm_iam.h"



#include <cbor.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_set_user_notification_categories_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "users", "{user}", "notification-categories",  NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_PUT, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    CborParser parser;
    CborValue value;
    const char* username = nabto_device_coap_request_get_parameter(request, "user");
    if (username == NULL || !nm_iam_cbor_init_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    struct nn_string_set categories;
    nn_string_set_init(&categories);
    if (!nm_iam_cbor_decode_string_set(&value, &categories)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    struct nn_string_map attributes;
    nn_string_map_init(&attributes);
    nn_string_map_insert(&attributes, "IAM:Username", username);

    if (!nm_iam_internal_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "IAM:SetUserNotificationCategories", &attributes)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        nn_string_set_deinit(&categories);
        nn_string_map_deinit(&attributes);
        return;
    }
    nn_string_map_deinit(&attributes);

    enum nm_iam_error err = nm_iam_internal_set_user_notification_categories(handler->iam, username, &categories);
    if (err == NM_IAM_ERROR_NO_SUCH_USER) {
        nabto_device_coap_error_response(request, 404, NULL);
    } else if (err == NM_IAM_ERROR_OK) {
        nabto_device_coap_response_set_code(request, 204);
        nabto_device_coap_response_ready(request);
    } else if (err == NM_IAM_ERROR_NO_SUCH_CATEGORY) {
        nabto_device_coap_error_response(request, 400, "One or more categories are invalid");
    } else {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
    }
    nn_string_set_deinit(&categories);
}
