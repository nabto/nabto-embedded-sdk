#include "heatpump_application.h"
#include "heatpump.hpp"
#include "nabto/nabto_device.h"
#include "nabto/nabto_device_experimental.h"

#include <cjson/cJSON.h>

#include <stdlib.h>
#include <stdbool.h>
#include <cbor.h>
#include <cbor_extra.h>

void heatpump_set_power(NabtoDeviceCoapRequest* request, void* userData);
void heatpump_set_mode(NabtoDeviceCoapRequest* request, void* userData);
void heatpump_set_target(NabtoDeviceCoapRequest* request, void* userData);
void heatpump_get(NabtoDeviceCoapRequest* request, void* userData);

void heatpump_coap_init(NabtoDevice* device, Heatpump* heatpump)
{
    const char* getState[] = { "heatpump", NULL };
    const char* postPower[] = { "heatpump", "power", NULL };
    const char* postMode[] = { "heatpump", "mode", NULL };
    const char* postTarget[] = { "heatpump", "target", NULL };
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_GET, getState, heatpump_get, heatpump);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_POST, postPower, heatpump_set_power, heatpump);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_POST, postMode, heatpump_set_mode, heatpump);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_POST, postTarget, heatpump_set_target, heatpump);
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
     nabto_device_coap_response_set_payload(response, message, strlen(message));
     nabto_device_coap_response_ready(response);
}

void heatpump_coap_send_bad_request(NabtoDeviceCoapRequest* request)
{
    heatpump_coap_send_error(request, 400, "Bad request");
}

void heatpump_coap_send_ok(NabtoDeviceCoapRequest* request, uint16_t code)
{
     NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
     nabto_device_coap_response_set_code(response, code);
     nabto_device_coap_response_ready(response);
}

// return true if action was allowed
bool heatpump_coap_check_action(NabtoDeviceCoapRequest* request, const char* action)
{
    NabtoDeviceIamEnv* iamEnv = nabto_device_iam_env_from_coap_request(request);
    NabtoDeviceError effect = nabto_device_iam_check_action(iamEnv, action);
    if (effect == NABTO_DEVICE_EC_OK) {
        return true;
    } else {
        // deny
        heatpump_coap_send_error(request, 403, "Unauthorized");
        return false;
    }
}

bool heatpump_init_cbor_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue)
{
    uint16_t contentFormat;
    NabtoDeviceError ec;
    ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        heatpump_coap_send_error(request, 400, "Invalid Content Format");
        return false;
    }
    void* payload;
    size_t payloadSize;
    if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
        heatpump_coap_send_error(request, 400, "Missing payload");
        return false;
    }
    cbor_parser_init((const uint8_t*)payload, payloadSize, 0, parser, 0);
    return true;
}

// Change heatpump power state (turn it on or off)
/**
 * Coap POST /heatpump/power,
 * Request, ContentFormat application/json
 * Data Boolean: true | false
 * Response, 200,
 */
void heatpump_set_power(NabtoDeviceCoapRequest* request, void* userData)
{
    Heatpump* application = (Heatpump*)userData;

    if (!heatpump_coap_check_action(request, "heatpump:SetPower")) {
        return;
    }

    CborParser parser;
    CborValue value;
    if (!heatpump_init_cbor_parser(request, &parser, &value)) {
        return;
    }

    bool powerState;
    if (!cbor_value_is_boolean(&value) || !cbor_value_get_boolean(&value, &powerState)) {
        heatpump_coap_send_error(request, 400, "Invalid request");
        return;
    }

    application->setPower(powerState);
    heatpump_coap_send_ok(request, 204);
}

// change heatpump mode
// CoAP post /heatpump/mode
// Data String: ("cool", "heat", "fan", "dry")

void heatpump_set_mode(NabtoDeviceCoapRequest* request, void* userData)
{
    Heatpump* application = (Heatpump*)userData;
    if (!heatpump_coap_check_action(request, "heatpump:SetMode")) {
        return;
    }

    CborParser parser;
    CborValue value;
    if (!heatpump_init_cbor_parser(request, &parser, &value)) {
        return;
    }

    if (!cbor_value_is_text_string(&value)) {
        return heatpump_coap_send_bad_request(request);
    }

    const char* cool = "COOL";
    const char* heat = "HEAT";
    const char* fan = "FAN";
    const char* dry = "DRY";
    bool match;

    if (cbor_value_text_string_equals(&value, cool, &match) && match) {
        application->setMode(Heatpump::Mode::COOL);
    } else if (cbor_value_text_string_equals(&value, heat, &match) && match) {
        application->setMode(Heatpump::Mode::HEAT);
    } else if (cbor_value_text_string_equals(&value, fan, &match) && match) {
        application->setMode(Heatpump::Mode::FAN);
    } else if (cbor_value_text_string_equals(&value, dry, &match) && match) {
        application->setMode(Heatpump::Mode::DRY);
    } else {
        return heatpump_coap_send_bad_request(request);
    }
    heatpump_coap_send_ok(request, 204);
}

// Set target temperature
// CoAP POST /heatpump/target
// Data double tempereature
void heatpump_set_target(NabtoDeviceCoapRequest* request, void* userData)
{
    Heatpump* application = (Heatpump*)userData;
    if (!heatpump_coap_check_action(request, "heatpump:SetTarget")) {
        return;
    }

    CborParser parser;
    CborValue value;
    if (!heatpump_init_cbor_parser(request, &parser, &value)) {
        return;
    }

    if (!cbor_value_is_floating_point(&value)) {
        return heatpump_coap_send_bad_request(request);
    }

    double target;
    if (!cbor_value_get_floating_point(&value, &target)) {
        return heatpump_coap_send_bad_request(request);
    }
    application->setTarget(target);
    heatpump_coap_send_ok(request, 204);
}

// Get heatpump state
// CoAP GET /heatpump
void heatpump_get(NabtoDeviceCoapRequest* request, void* userData)
{
    Heatpump* application = (Heatpump*)userData;
    if (!heatpump_coap_check_action(request, "heatpump:GetState")) {
        return;
    }

    uint8_t buffer[128];
    CborEncoder encoder;
    cbor_encoder_init(&encoder, buffer, 128, 0);

    CborEncoder map;
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "power");
    cbor_encode_boolean(&map, application->getPower());

    cbor_encode_text_stringz(&map, "mode");
    cbor_encode_text_stringz(&map, application->getModeString());

    cbor_encode_text_stringz(&map, "temperature");
    cbor_encode_double(&map, application->getTemperature());

    cbor_encode_text_stringz(&map, "target");
    cbor_encode_double(&map, application->getTarget());

    CborError ec = cbor_encoder_close_container(&encoder, &map);
    if (ec) {
        return heatpump_coap_send_error(request, 500, "Internal error");
    }

    NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
    nabto_device_coap_response_set_code(response, 200);
    nabto_device_coap_response_set_content_format(response, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_device_coap_response_set_payload(response, buffer, cbor_encoder_get_buffer_size(&encoder, buffer));
    nabto_device_coap_response_ready(response);
}
