#include <nabto/nabto_device.h>
#include "nm_iam_coap_handler.h"

#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_allocator.h"



static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_device_info_set_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "device-info", "{key}", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_PUT, paths, &handle_request);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct nm_iam* iam = handler->iam;
    NabtoDeviceConnectionRef conn = nabto_device_coap_request_get_connection_ref(request);
    if (!nm_iam_internal_check_access(handler->iam, conn , "IAM:SetDeviceInfo", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    CborParser parser;
    CborValue value;

    const char* key = nabto_device_coap_request_get_parameter(request, "key");
    if (key == NULL) {
        nabto_device_coap_error_response(request, 500, NULL);
        return;
    }

    if (!nm_iam_cbor_init_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    if (strcmp(key, "friendly-name") == 0) {
        char* fn = NULL;
        if (!nm_iam_cbor_decode_string(&value, &fn) || fn == NULL) {
            nabto_device_coap_error_response(request, 400, "Friendly name missing");
            return;
        } else if (strlen(fn) > iam->friendlyNameMaxLength) {
            nabto_device_coap_error_response(request, 400, "Friendly name length exceeded");
            nm_iam_free(fn);
            return;
        }

        nm_iam_state_set_friendly_name(iam->state, fn);
        nabto_device_mdns_add_txt_item(handler->device, "fn", fn);
        nm_iam_internal_state_has_changed(iam);
        nm_iam_free(fn);
    } else {
        nabto_device_coap_error_response(request, 404, "No such key");
        return;
    }

    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
}
