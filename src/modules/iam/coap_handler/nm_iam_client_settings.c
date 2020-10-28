#include "nm_iam_coap_handler.h"
#include "../nm_iam.h"
#include "../nm_iam_internal.h"
#include "../nm_iam_user.h"


#include <stdlib.h>

static void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError nm_iam_client_settings_init(struct nm_iam_coap_handler* handler, NabtoDevice* device, struct nm_iam* iam)
{
    const char* paths[] = { "iam", "pairing", "client-settings", NULL };
    return nm_iam_coap_handler_init(handler, device, iam, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}


static size_t encode_response(struct nm_iam* iam, struct nm_iam_user* user, void* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    if (user->serverConnectToken != NULL) {
        cbor_encode_text_stringz(&map, "ServerConnectToken");
        cbor_encode_text_stringz(&map, user->serverConnectToken);
    }

    cbor_encoder_close_container(&encoder, &map);

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}

void handle_request(struct nm_iam_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    if (!nm_iam_check_access(handler->iam, nabto_device_coap_request_get_connection_ref(request), "Pairing:Get", NULL)) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        return;
    }

    struct nm_iam_user* user = nm_iam_find_user_by_coap_request(handler->iam, request);

    if (user == NULL) {
        nabto_device_coap_error_response(request, 403, "Not paired");
        return;
    }

    size_t payloadSize = encode_response(handler->iam, user, NULL, 0);
    uint8_t* payload = malloc(payloadSize);
    if (payload == NULL) {
        return;
    }

    encode_response(handler->iam, user, payload, payloadSize);

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
