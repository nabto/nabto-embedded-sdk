#include "heat_pump_coap_handler.h"
#include "heat_pump_state.h"
#include "heat_pump.h"

#include <cbor.h>
#include <cbor_extra.h>

static void handle_request(struct heat_pump_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError heat_pump_set_target_init(struct heat_pump_coap_handler* handler, NabtoDevice* device, struct heat_pump* heatPump)
{
    const char* paths[] = { "heat-pump", "target", NULL };
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

    double target;
    if (cbor_value_get_floating_point(&value, &target) != CborNoError) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }
    heat_pump_set_target(heatPump, target);

    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
}
