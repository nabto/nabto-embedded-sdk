#include "nm_iam_coap_handler.h"
#include <nabto/nabto_device_experimental.h>

#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_pairing.h"

#include "../nm_iam_allocator.h"



static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_pairing_get_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "pairing", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

static size_t encode_response(struct nm_iam* iam, void* buffer, size_t bufferSize, NabtoDeviceConnectionRef conn)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    CborEncoder array;

    if (nm_iam_cbor_err_not_oom(cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength)) ||
        nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "Modes")) ||
        nm_iam_cbor_err_not_oom(cbor_encoder_create_array(&map, &array, CborIndefiniteLength))) {
        return 0;
    }


    if (nm_iam_pairing_is_password_open_possible(iam, conn) &&
        nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&array, "PasswordOpen"))) {
            return 0;
    }

    if (nm_iam_pairing_is_local_open_possible(iam, conn) &&
        nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&array, "LocalOpen"))) {
        return 0;
    }

    if (nm_iam_pairing_is_password_invite_possible(iam, conn) &&
        nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&array, "PasswordInvite"))) {
        return 0;
    }

    if (nm_iam_pairing_is_local_initial_possible(iam, conn) &&
        nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&array, "LocalInitial"))) {
        return 0;
    }

    if (nm_iam_cbor_err_not_oom(cbor_encoder_close_container(&map, &array))) {
        return 0;
    }

    const char* nabtoVersion = nabto_device_version();
    const char* appName = nabto_device_get_app_name(iam->device);
    const char* appVersion = nabto_device_get_app_version(iam->device);
    const char* productId = nabto_device_get_product_id(iam->device);
    const char* deviceId = nabto_device_get_device_id(iam->device);

    if (nabtoVersion) {
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "NabtoVersion")) ||
            nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, nabtoVersion))) {
            return 0;
        }
    }

    if (appVersion) {
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "AppVersion")) ||
            nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, appVersion))) {
            return 0;
        }
    }

    if (appName) {
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "AppName")) ||
            nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, appName))) {
            return 0;
        }
    }

    if (productId) {
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "ProductId")) ||
            nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, productId))) {
            return 0;
        }
    }

    if (deviceId) {
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "DeviceId")) ||
            nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, deviceId))) {
            return 0;
        }
    }

    if (iam->state->friendlyName) {
        if (nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, "FriendlyName")) ||
            nm_iam_cbor_err_not_oom(cbor_encode_text_stringz(&map, iam->state->friendlyName))) {
            return 0;
        }
    }

    if (nm_iam_cbor_err_not_oom(cbor_encoder_close_container(&encoder, &map))) {
        return 0;
    }

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}


void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    NabtoDeviceConnectionRef conn = nabto_device_coap_request_get_connection_ref(request);
    if (!nm_iam_internal_check_access(handler->iam, conn , "IAM:GetPairing", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    size_t payloadSize = encode_response(handler->iam, NULL, 0, conn);
    uint8_t* payload = nm_iam_calloc(1, payloadSize);
    if (payload == NULL) {
        return;
    }

    encode_response(handler->iam, payload, payloadSize, conn);

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
