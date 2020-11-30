#include "heat_pump_coap_handler.h"
#include "heat_pump_state.h"
#include "heat_pump.h"

#include <cbor.h>

static void handle_request(struct heat_pump_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError heat_pump_set_mode_init(struct heat_pump_coap_handler* handler, NabtoDevice* device, struct heat_pump* heatPump)
{
    const char* paths[] = { "heat-pump", "mode", NULL };
    return heat_pump_coap_handler_init(handler, device, heatPump, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

void handle_request(struct heat_pump_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct heat_pump* heatPump = handler->heatPump;
    if (!heat_pump_check_access(heatPump, request, "HeatPump:Set")) {
        nabto_device_coap_error_response(request, 403, "Access denied");
        return;
    }

    CborParser parser;
    CborValue value;
    if (!heat_pump_init_cbor_parser(request, &parser, &value)) {
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
        heat_pump_set_mode(heatPump, HEAT_PUMP_MODE_COOL);
    } else if ((cbor_value_text_string_equals(&value, heat, &match) == CborNoError) && match) {
        heat_pump_set_mode(heatPump, HEAT_PUMP_MODE_HEAT);
    } else if ((cbor_value_text_string_equals(&value, fan, &match) == CborNoError) && match) {
        heat_pump_set_mode(heatPump, HEAT_PUMP_MODE_FAN);
    } else if ((cbor_value_text_string_equals(&value, dry, &match) == CborNoError) && match) {
        heat_pump_set_mode(heatPump, HEAT_PUMP_MODE_DRY);
    } else {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }

    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
}
