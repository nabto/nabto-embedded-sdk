#include "thermostat_coap_handler.h"
#include "thermostat.h"

#include <stdlib.h>
#include <tinycbor/cbor.h>

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


void handle_request(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct thermostat* thermostat = handler->thermostat;
    if (!thermostat_check_access(thermostat, request, "Thermostat:Get")) {
        nabto_device_coap_error_response(request, 403, "Access denied");
        return;
    }

    uint8_t* payload = malloc(THERMOSTAT_STATE_CBOR_CAPACITY);
    if (payload == NULL) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
        return;
    }

    size_t payloadSize = thermostat_state_encode(thermostat->state, payload, THERMOSTAT_STATE_CBOR_CAPACITY);
    if (payloadSize == 0) {
        free(payload);
        nabto_device_coap_error_response(request, 500, "Cannot encode state");
        return;
    }

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
