#include <nabto/nabto_device_experimental.h>
#include "nm_iam_coap_handler.h"

#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_pairing.h"

#include "../nm_iam_allocator.h"



static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_settings_get_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "settings", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

static size_t encode_response(struct nm_iam* iam, void* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    CborError ec = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (ec != CborNoError) {
        return 0;
    }

    ec = cbor_encode_text_stringz(&map, "PasswordOpenPairing");
    if (ec != CborNoError) {
        return 0;
    }
    ec = cbor_encode_boolean(&map, iam->state->passwordOpenPairing);
    if (ec != CborNoError) {
        return 0;
    }

    ec = cbor_encode_text_stringz(&map, "PasswordInvitePairing");
    if (ec != CborNoError) {
        return 0;
    }
    ec = cbor_encode_boolean(&map, iam->state->passwordInvitePairing);
    if (ec != CborNoError) {
        return 0;
    }

    ec = cbor_encode_text_stringz(&map, "LocalOpenPairing");
    if (ec != CborNoError) {
        return 0;
    }
    ec = cbor_encode_boolean(&map, iam->state->localOpenPairing);
    if (ec != CborNoError) {
        return 0;
    }

    const char* sct = iam->state->passwordOpenSct;
    if (sct) {
        ec = cbor_encode_text_stringz(&map, "PasswordOpenSct");
        if (ec != CborNoError) {
            return 0;
        }
        ec = cbor_encode_text_stringz(&map, sct);
        if (ec != CborNoError) {
            return 0;
        }
    }

    const char* pwd = iam->state->passwordOpenPassword;
    if (pwd) {
        ec = cbor_encode_text_stringz(&map, "PasswordOpenPassword");
        if (ec != CborNoError) {
            return 0;
        }
        ec = cbor_encode_text_stringz(&map, pwd);
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
    if (!nm_iam_internal_check_access(handler->iam, conn , "IAM:GetSettings", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    size_t payloadSize = encode_response(handler->iam, NULL, 0);
    uint8_t* payload = nm_iam_calloc(1, payloadSize);
    if (payload == NULL) {
        return;
    }

    encode_response(handler->iam, payload, payloadSize);

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
