#include "thermostat_coap_handler.h"
#include "thermostat_state.h"
#include "thermostat.h"

#include <cbor.h>
#include <stdlib.h>

static void handle_request(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError thermostat_get_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat)
{
    const char* paths[] = { "thermostat", NULL };
    return thermostat_coap_handler_init(handler, device, thermostat, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

NabtoDeviceError thermostat_get_legacy_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat)
{
    const char* paths[] = { "heat-pump", NULL };
    return thermostat_coap_handler_init(handler, device, thermostat, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}


static size_t encode(struct thermostat* thermostat, void* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "Mode");
    cbor_encode_text_stringz(&map, mode_as_string(thermostat->state.mode));

    cbor_encode_text_stringz(&map, "Target");
    cbor_encode_double(&map, thermostat->state.target);

    cbor_encode_text_stringz(&map, "Power");
    cbor_encode_boolean(&map, thermostat->state.power);

    cbor_encode_text_stringz(&map, "Temperature");
    cbor_encode_double(&map, thermostat->state.temperature);

    cbor_encoder_close_container(&encoder, &map);

    return cbor_encoder_get_extra_bytes_needed(&encoder);
}

void handle_request(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct thermostat* thermostat = handler->thermostat;
    if (!thermostat_check_access(thermostat, request, "Thermostat:Get")) {
        nabto_device_coap_error_response(request, 403, "Access denied");
        return;
    }

    size_t payloadSize = encode(thermostat, NULL, 0);
    uint8_t* payload = malloc(payloadSize);
    if (payload == NULL) {
        return;
    }

    encode(thermostat, payload, payloadSize);

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
