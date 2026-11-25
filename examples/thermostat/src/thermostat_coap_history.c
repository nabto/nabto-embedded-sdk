#include "thermostat_coap_handler.h"
#include "thermostat.h"
#include "thermostat_history.h"

#include <stdlib.h>
#include <tinycbor/cbor.h>

static void handle_request(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError thermostat_get_history_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat)
{
    const char* paths[] = { "thermostat", "history", NULL };
    return thermostat_coap_handler_init(handler, device, thermostat, NABTO_DEVICE_COAP_GET, paths, &handle_request);
}

static size_t encode(const double* samples, size_t count, void* buffer, size_t bufferSize)
{
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, bufferSize, 0);
    CborEncoder map;
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "Interval");
    cbor_encode_uint(&map, THERMOSTAT_HISTORY_INTERVAL_SECONDS);

    cbor_encode_text_stringz(&map, "Samples");
    CborEncoder array;
    cbor_encoder_create_array(&map, &array, count);
    for (size_t i = 0; i < count; i++) {
        cbor_encode_double(&array, samples[i]);
    }
    cbor_encoder_close_container(&map, &array);

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

    double samples[THERMOSTAT_HISTORY_CAPACITY];
    size_t count = thermostat_history_snapshot(&thermostat->history, samples, THERMOSTAT_HISTORY_CAPACITY);

    size_t payloadSize = encode(samples, count, NULL, 0);
    uint8_t* payload = malloc(payloadSize);
    if (payload == NULL) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        return;
    }

    encode(samples, count, payload, payloadSize);

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
