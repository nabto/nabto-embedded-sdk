#include <nabto/nabto_device_experimental.h>
#include "nm_iam_coap_handler.h"

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
    CborError ec = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (ec != CborNoError) {
        return 0;
    }

    ec = cbor_encode_text_stringz(&map, "Modes");
    if (ec != CborNoError) {
        return 0;
    }

    CborEncoder array;
    ec = cbor_encoder_create_array(&map, &array, CborIndefiniteLength);
    if (ec != CborNoError) {
        return 0;
    }

    if (nm_iam_pairing_is_password_open_possible(iam, conn)) {
        ec = cbor_encode_text_stringz(&array, "PasswordOpen");
        if (ec != CborNoError) {
            return 0;
        }
    }

    if (nm_iam_pairing_is_local_open_possible(iam, conn)) {
        ec = cbor_encode_text_stringz(&array, "LocalOpen");
        if (ec != CborNoError) {
            return 0;
        }
    }

    if (nm_iam_pairing_is_password_invite_possible(iam, conn)) {
        ec = cbor_encode_text_stringz(&array, "PasswordInvite");
        if (ec != CborNoError) {
            return 0;
        }
    }

    if (nm_iam_pairing_is_local_initial_possible(iam, conn)) {
        ec = cbor_encode_text_stringz(&array, "LocalInitial");
        if (ec != CborNoError) {
            return 0;
        }
    }

    ec = cbor_encoder_close_container(&map, &array);
    if (ec != CborNoError) {
        return 0;
    }

    const char* nabtoVersion = nabto_device_version();
    const char* appName = nabto_device_get_app_name(iam->device);
    const char* appVersion = nabto_device_get_app_version(iam->device);
    const char* productId = nabto_device_get_product_id(iam->device);
    const char* deviceId = nabto_device_get_device_id(iam->device);

    if (nabtoVersion) {
        ec = cbor_encode_text_stringz(&map, "NabtoVersion");
        if (ec != CborNoError) {
            return 0;
        }
        ec = cbor_encode_text_stringz(&map, nabtoVersion);
        if (ec != CborNoError) {
            return 0;
        }
    }

    if (appVersion) {
        ec = cbor_encode_text_stringz(&map, "AppVersion");
        if (ec != CborNoError) {
            return 0;
        }
        ec = cbor_encode_text_stringz(&map, appVersion);
        if (ec != CborNoError) {
            return 0;
        }
    }

    if (appName) {
        ec = cbor_encode_text_stringz(&map, "AppName");
        if (ec != CborNoError) {
            return 0;
        }
        ec = cbor_encode_text_stringz(&map, appName);
        if (ec != CborNoError) {
            return 0;
        }
    }

    if (productId) {
        ec = cbor_encode_text_stringz(&map, "ProductId");
        if (ec != CborNoError) {
            return 0;
        }
        ec = cbor_encode_text_stringz(&map, productId);
        if (ec != CborNoError) {
            return 0;
        }
    }

    if (deviceId) {
        ec = cbor_encode_text_stringz(&map, "DeviceId");
        if (ec != CborNoError) {
            return 0;
        }
        ec = cbor_encode_text_stringz(&map, deviceId);
        if (ec != CborNoError) {
            return 0;
        }
    }

    if (iam->state->friendlyName) {
        ec = cbor_encode_text_stringz(&map, "FriendlyName");
        if (ec != CborNoError) {
            return 0;
        }
        ec = cbor_encode_text_stringz(&map, iam->state->friendlyName);
        if (ec != CborNoError) {
            return 0;
        }
    }

    ec = cbor_encoder_close_container(&encoder, &map);
    if (ec != CborNoError) {
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
