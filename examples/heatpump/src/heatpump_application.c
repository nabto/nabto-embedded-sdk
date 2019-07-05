#include "heatpump_application.h"

struct heatpump_application_state* heatpump_application_state_new()
{
    struct heatpump_application_state* state = (struct heatpump_application_state*)malloc(sizeof(struct heatpump_application_state));

    state->powerState = HEATPUMP_POWER_STATE_ON;
    state->roomTemperature = 19;
    state->targetTemperature = 23;
    state->mode = HEATPUMP_MODE_HEAT;
}

void heatpump_application_state_free(struct heatpump_application_state* state)
{
    free(state);
}

void heatpump_coap_send_error(NabtoDeviceCoapRequest* request, uint16_t code, const char* message)
{
     NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
     nabto_device_coap_response_set_code(response, code);
     nabto_device_coap_response_set_content_format(response, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
     nabto_device_coap_response_set_payload(response, message);
     nabto_device_coap_response_ready(response);
}

// Change heatpump power state (turn it on or off)
/**
 * Coap POST /heatpump/state,
 * Request, ContentFormat application/json
 * {
 *   "state": "ON"
 * }
 * Response, 200,
 */
void heatpump_set_state(NabtoDeviceCoapRequest* request)
{
    uint16_t contentFormat;
    NabtoDeviceError ec;
    ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_JSON) {
        heatpump_coap_error(request, 400, "Invalid Content Format");
            return;
    }
    NabtoDeviceCoapResponse* response = nabto_device_coap_create_response();

}

// change heatpump mode
// CoAP post /heatpump/mode
void heatpump_set_mode()
{

}

// Set target temperature
// CoAP POST /heatpump/target
void heatpump_set_target_temperature()
{

}

// Get heatpump state
// CoAP GET /heatpump
void heatpump_get()
{

}
