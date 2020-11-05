#include <nabto/nabto_device_experimental.h>
#include "nm_iam_coap_handler.h"

#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_pairing.h"

#include <stdlib.h>

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
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "Modes");

    CborEncoder array;
    cbor_encoder_create_array(&map, &array, CborIndefiniteLength);

    if (nm_iam_pairing_is_password_possible(iam, conn)) {
        cbor_encode_text_stringz(&array, "PasswordOpen");
    }

    if (nm_iam_pairing_is_local_possible(iam, conn)) {
        cbor_encode_text_stringz(&array, "LocalOpen");
    }

    if (nm_iam_pairing_is_password_invite_possible(iam, conn)) {
        cbor_encode_text_stringz(&array, "PasswordInvite");
    }

    if (nm_iam_pairing_is_local_initial_possible(iam, conn)) {
        cbor_encode_text_stringz(&array, "LocalInitial"); 
    }

    cbor_encoder_close_container(&map, &array);

    const char* nabtoVersion = nabto_device_version();
    const char* appName = nabto_device_get_app_name(iam->device);
    const char* appVersion = nabto_device_get_app_version(iam->device);
    const char* productId = nabto_device_get_product_id(iam->device);
    const char* deviceId = nabto_device_get_device_id(iam->device);

    if (nabtoVersion) {
        cbor_encode_text_stringz(&map, "NabtoVersion");
        cbor_encode_text_stringz(&map, nabtoVersion);
    }

    if (appVersion) {
        cbor_encode_text_stringz(&map, "AppVersion");
        cbor_encode_text_stringz(&map, appVersion);
    }

    if (appName) {
        cbor_encode_text_stringz(&map, "AppName");
        cbor_encode_text_stringz(&map, appName);
    }

    if (productId) {
        cbor_encode_text_stringz(&map, "ProductId");
        cbor_encode_text_stringz(&map, productId);
    }

    if (deviceId) {
        cbor_encode_text_stringz(&map, "DeviceId");
        cbor_encode_text_stringz(&map, deviceId);
    }
    cbor_encoder_close_container(&encoder, &map);

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}


void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    NabtoDeviceConnectionRef conn = nabto_device_coap_request_get_connection_ref(request);
    if (!nm_iam_check_access(handler->iam, conn , "IAM:GetPairing", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    size_t payloadSize = encode_response(handler->iam, NULL, 0, conn);
    uint8_t* payload = malloc(payloadSize);
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
    free(payload);
}
