#include "thermostat_coap_handler.h"
#include "thermostat_state.h"
#include "thermostat.h"

#include <cbor.h>

static void handle_request(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError thermostat_set_mode_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat)
{
    const char* paths[] = { "thermostat", "mode", NULL };
    return thermostat_coap_handler_init(handler, device, thermostat, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

NabtoDeviceError thermostat_set_mode_legacy_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat)
{
    const char* paths[] = { "heat-pump", "mode", NULL };
    return thermostat_coap_handler_init(handler, device, thermostat, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}


void handle_request(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct thermostat* thermostat = handler->thermostat;
    if (!thermostat_check_access(thermostat, request, "Thermostat:Set")) {
        nabto_device_coap_error_response(request, 403, "Access denied");
        return;
    }

    CborParser parser;
    CborValue value;
    if (!thermostat_init_cbor_parser(request, &parser, &value)) {
        return;
    }

    if (!cbor_value_is_text_string(&value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    const char* cool = "COOL";
    const char* heat = "HEAT";
    const char* fan = "FAN";
    const char* dry = "DRY";
    bool match;

    if ((cbor_value_text_string_equals(&value, cool, &match) == CborNoError) && match) {
        thermostat_set_mode(thermostat, THERMOSTAT_MODE_COOL);
    } else if ((cbor_value_text_string_equals(&value, heat, &match) == CborNoError) && match) {
        thermostat_set_mode(thermostat, THERMOSTAT_MODE_HEAT);
    } else if ((cbor_value_text_string_equals(&value, fan, &match) == CborNoError) && match) {
        thermostat_set_mode(thermostat, THERMOSTAT_MODE_FAN);
    } else if ((cbor_value_text_string_equals(&value, dry, &match) == CborNoError) && match) {
        thermostat_set_mode(thermostat, THERMOSTAT_MODE_DRY);
    } else {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
}
