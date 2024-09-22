#include "thermostat_coap_handler.h"
#include "thermostat.h"

#include <tinycbor/cbor.h>
#include "cbor_extra.h"

static void handle_request(struct thermostat_coap_handler* handler, NabtoDeviceCoapRequest* request);

NabtoDeviceError thermostat_set_target_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat)
{
    const char* paths[] = { "thermostat", "target", NULL };
    return thermostat_coap_handler_init(handler, device, thermostat, NABTO_DEVICE_COAP_POST, paths, &handle_request);
}

NabtoDeviceError thermostat_set_target_legacy_init(struct thermostat_coap_handler* handler, NabtoDevice* device, struct thermostat* thermostat)
{
    const char* paths[] = { "heat-pump", "target", NULL };
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

    double target;
    if (cbor_value_get_floating_point(&value, &target) != CborNoError) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        return;
    }
    thermostat_state_set_target(state, target);

    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
}
