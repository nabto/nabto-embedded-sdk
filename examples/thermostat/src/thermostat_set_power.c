#include "thermostat_coap_handler.h"
#include "thermostat.h"

#include <tinycbor/cbor.h>

static void handle_request(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError thermostat_set_power_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat)
{
    const char* paths[] = { "thermostat", "power", NULL };
    return thermostat_coap_handler_init(handler, device, thermostat, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

NabtoDeviceError thermostat_set_power_legacy_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat)
{
    const char* paths[] = { "heat-pump", "power", NULL };
    return thermostat_coap_handler_init(handler, device, thermostat, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}


void handle_request(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request)
{
    struct thermostat* thermostat = handler->thermostat;
    struct thermostat_state* state = thermostat->state;
    if (!thermostat_check_access(thermostat, request, "Thermostat:Set")) {
        nabto_device_coap_error_response(request, 403, "Access denied");
        return;
    }
    CborParser parser;
    CborValue value;
    if (!thermostat_init_cbor_parser(request, &parser, &value)) {
        nabto_device_coap_error_response(request, 400, "Invalid request");
        return;
    }

    bool powerState;
    if (!cbor_value_is_boolean(&value) || cbor_value_get_boolean(&value, &powerState) != CborNoError) {
        nabto_device_coap_error_response(request, 400, "Invalid request");
        return;
    }

    thermostat_state_set_power(state, powerState);
    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
}
