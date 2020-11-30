#include "heat_pump_coap_handler.h"
#include "heat_pump_state.h"
#include "heat_pump.h"

#include <cbor.h>

static void handle_request(struct heat_pump_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError heat_pump_set_power_init(struct heat_pump_coap_handler* handler, NabtoDevice* device, struct heat_pump* heatPump)
{
    const char* paths[] = { "heat-pump", "power", NULL };
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
        nabto_device_coap_error_response(request, 400, "Invalid request");
        return;
    }

    bool powerState;
    if (!cbor_value_is_boolean(&value) || cbor_value_get_boolean(&value, &powerState) != CborNoError) {
        nabto_device_coap_error_response(request, 400, "Invalid request");
        return;
    }

    heat_pump_set_power(heatPump, powerState);
    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
}
