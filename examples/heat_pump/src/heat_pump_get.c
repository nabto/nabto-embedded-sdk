#include "heat_pump_coap_handler.h"
#include "heat_pump_state.h"
#include "heat_pump.h"

#include <cbor.h>
#include <stdlib.h>

static void handle_request(struct heat_pump_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError heat_pump_get_init(struct heat_pump_coap_handler* handler, NabtoDevice* device, struct heat_pump* heatPump)
{
    const char* paths[] = { "heat-pump", NULL };
    return heat_pump_coap_handler_init(handler, device, heatPump, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

static size_t encode(struct heat_pump* heatPump, void* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "Mode");
    cbor_encode_text_stringz(&map, mode_as_string(heatPump->state.mode));

    cbor_encode_text_stringz(&map, "Target");
    cbor_encode_double(&map, heatPump->state.target);

    cbor_encode_text_stringz(&map, "Power");
    cbor_encode_boolean(&map, heatPump->state.power);

    cbor_encode_text_stringz(&map, "Temperature");
    cbor_encode_double(&map, 22.3);
    
    cbor_encoder_close_container(&encoder, &map);

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}

void handle_request(struct heat_pump_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct heat_pump* heatPump = handler->heatPump;
    if (!heat_pump_check_access(heatPump, request, "HeatPump:Get")) {
        nabto_device_coap_error_response(request, 403, "Access denied");
        return;
    }

    size_t payloadSize = encode(heatPump, NULL, 0);
    uint8_t* payload = malloc(payloadSize);
    if (payload == NULL) {
        return;
    }

    encode(heatPump, payload, payloadSize);

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
