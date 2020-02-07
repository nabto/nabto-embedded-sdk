#include "heat_pump_coap.hpp"
#include "heat_pump.hpp"
#include "nabto/nabto_device.h"
#include "nabto/nabto_device_experimental.h"

#include <modules/fingerprint_iam/fingerprint_iam.hpp>

#include <stdlib.h>
#include <stdbool.h>
#include <cbor.h>
#include <cbor_extra.h>

#include <mutex>
#include <thread>
#include <condition_variable>
#include <iostream>

void heat_pump_set_power(NabtoDeviceCoapRequest* request, void* userData);
void heat_pump_set_mode(NabtoDeviceCoapRequest* request, void* userData);
void heat_pump_set_target(NabtoDeviceCoapRequest* request, void* userData);
void heat_pump_get(NabtoDeviceCoapRequest* request, void* userData);
void heat_pump_pairing_button(NabtoDeviceCoapRequest* request, void* userData);
void heat_pump_get_client_settings(NabtoDeviceCoapRequest* request, void* userData);


HeatPumpCoapRequestHandler::HeatPumpCoapRequestHandler(HeatPump* hp, NabtoDeviceCoapMethod method, const char** pathSegments, CoapHandler handler)
    : heatPump_(hp), handler_(handler)
{
    future_ = nabto_device_future_new(hp->getDevice());
    listener_ = nabto_device_listener_new(hp->getDevice());
    if (!future_ || !listener_) {
        return;
    }
    nabto_device_coap_init_listener(hp->getDevice(), listener_, method, pathSegments);
    startListen();
}

void HeatPumpCoapRequestHandler::startListen()
{
    nabto_device_listener_new_coap_request(listener_, future_, &request_);
    nabto_device_future_set_callback(future_, HeatPumpCoapRequestHandler::requestCallback, this);
}

void heat_pump_coap_init(NabtoDevice* device, HeatPump* heatPump)
{
    const char* getState[] = { "heat-pump", NULL };
    const char* postPower[] = { "heat-pump", "power", NULL };
    const char* postMode[] = { "heat-pump", "mode", NULL };
    const char* postTarget[] = { "heat-pump", "target", NULL };
    const char* getClientSettings[] = { "beta", "client-settings", NULL };

    heatPump->coapGetState = std::make_unique<HeatPumpCoapRequestHandler>(heatPump, NABTO_DEVICE_COAP_GET, getState, &heat_pump_get);
    heatPump->coapPostPower = std::make_unique<HeatPumpCoapRequestHandler>(heatPump, NABTO_DEVICE_COAP_POST, postPower, &heat_pump_set_power);
    heatPump->coapPostMode = std::make_unique<HeatPumpCoapRequestHandler>(heatPump, NABTO_DEVICE_COAP_POST, postMode, &heat_pump_set_mode);
    heatPump->coapPostTarget = std::make_unique<HeatPumpCoapRequestHandler>(heatPump, NABTO_DEVICE_COAP_POST, postTarget, &heat_pump_set_target);
    heatPump->coapGetClientSettings = std::make_unique<HeatPumpCoapRequestHandler>(heatPump, NABTO_DEVICE_COAP_GET, getClientSettings, &heat_pump_get_client_settings);
}

void heat_pump_coap_deinit(HeatPump* heatPump)
{
    heatPump->coapGetState->stopListen();
    heatPump->coapPostPower->stopListen();
    heatPump->coapPostMode->stopListen();
    heatPump->coapPostTarget->stopListen();
    heatPump->coapGetClientSettings->stopListen();
}

void heat_pump_coap_send_bad_request(NabtoDeviceCoapRequest* request)
{
    nabto_device_coap_error_response(request, 400, "Bad request");
    nabto_device_coap_request_free(request);
}

void heat_pump_coap_send_ok(NabtoDeviceCoapRequest* request, uint16_t code)
{
     nabto_device_coap_response_set_code(request, code);
     nabto_device_coap_response_ready(request);
     nabto_device_coap_request_free(request);
}

// return true if action was allowed
bool heat_pump_coap_check_action(nabto::FingerprintIAM* fingerprintIAM, NabtoDeviceCoapRequest* request, const char* action)
{
    nabto::iam::Attributes attributes;
    if (!fingerprintIAM->checkAccess(nabto_device_coap_request_get_connection_ref(request), std::string(action), attributes)) {
        nabto_device_coap_error_response(request, 403, "Unauthorized");
        nabto_device_coap_request_free(request);
        return false;
    }
    return true;
}

bool heat_pump_init_cbor_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue)
{
    uint16_t contentFormat;
    NabtoDeviceError ec;
    ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        nabto_device_coap_error_response(request, 400, "Invalid Content Format");
        nabto_device_coap_request_free(request);
        return false;
    }
    void* payload;
    size_t payloadSize;
    if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 400, "Missing payload");
        nabto_device_coap_request_free(request);
        return false;
    }
    cbor_parser_init((const uint8_t*)payload, payloadSize, 0, parser, cborValue);
    return true;
}

// Change heat_pump power state (turn it on or off)
/**
 * Coap POST /heat_pump/power,
 * Request, ContentFormat application/json
 * Data Boolean: true | false
 * Response, 200,
 */
void heat_pump_set_power(NabtoDeviceCoapRequest* request, void* userData)
{
    HeatPump* application = (HeatPump*)userData;

    if (!heat_pump_coap_check_action(application->getFPIAM(), request, "HeatPump:Set")) {
        return;
    }

    CborParser parser;
    CborValue value;
    if (!heat_pump_init_cbor_parser(request, &parser, &value)) {
        return;
    }

    bool powerState;
    if (!cbor_value_is_boolean(&value) || cbor_value_get_boolean(&value, &powerState) != CborNoError) {
        nabto_device_coap_error_response(request, 400, "Invalid request");
        nabto_device_coap_request_free(request);
        return;
    }

    application->setPower(powerState);
    heat_pump_coap_send_ok(request, 204);
}

// change heat_pump mode
// CoAP post /heat_pump/mode
// Data String: ("cool", "heat", "fan", "dry")
void heat_pump_set_mode(NabtoDeviceCoapRequest* request, void* userData)
{
    HeatPump* application = (HeatPump*)userData;
    if (!heat_pump_coap_check_action(application->getFPIAM(), request, "HeatPump:Set")) {
        return;
    }

    CborParser parser;
    CborValue value;
    if (!heat_pump_init_cbor_parser(request, &parser, &value)) {
        return;
    }

    if (!cbor_value_is_text_string(&value)) {
        return heat_pump_coap_send_bad_request(request);
    }

    const char* cool = "COOL";
    const char* heat = "HEAT";
    const char* fan = "FAN";
    const char* dry = "DRY";
    bool match;

    if ((cbor_value_text_string_equals(&value, cool, &match) == CborNoError) && match) {
        application->setMode(HeatPump::Mode::COOL);
    } else if ((cbor_value_text_string_equals(&value, heat, &match) == CborNoError) && match) {
        application->setMode(HeatPump::Mode::HEAT);
    } else if ((cbor_value_text_string_equals(&value, fan, &match) == CborNoError) && match) {
        application->setMode(HeatPump::Mode::FAN);
    } else if ((cbor_value_text_string_equals(&value, dry, &match) == CborNoError) && match) {
        application->setMode(HeatPump::Mode::DRY);
    } else {
        return heat_pump_coap_send_bad_request(request);
    }
    heat_pump_coap_send_ok(request, 204);
}

// Set target temperature
// CoAP POST /heat_pump/target
// Data double tempereature
void heat_pump_set_target(NabtoDeviceCoapRequest* request, void* userData)
{
    HeatPump* application = (HeatPump*)userData;
    if (!heat_pump_coap_check_action(application->getFPIAM(), request, "HeatPump:Set")) {
        return;
    }

    CborParser parser;
    CborValue value;
    if (!heat_pump_init_cbor_parser(request, &parser, &value)) {
        return;
    }

    if (!cbor_value_is_floating_point(&value)) {
        return heat_pump_coap_send_bad_request(request);
    }

    double target;
    if (cbor_value_get_floating_point(&value, &target) != CborNoError) {
        return heat_pump_coap_send_bad_request(request);
    }
    application->setTarget(target);
    heat_pump_coap_send_ok(request, 204);
}

// Get heat_pump state
// CoAP GET /heat_pump
void heat_pump_get(NabtoDeviceCoapRequest* request, void* userData)
{
    HeatPump* application = (HeatPump*)userData;
    if (!heat_pump_coap_check_action(application->getFPIAM(), request, "HeatPump:Get")) {
        return;
    }

    auto d = json::to_cbor(application->getState());

    nabto_device_coap_response_set_code(request, 205);
    nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, d.data(), d.size());
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
    } else {
        nabto_device_coap_response_ready(request);
    }
    nabto_device_coap_request_free(request);
}


// Get heat_pump client settings
// CoAP GET /beta/client-settings
// return ServerKey and ServerUrl
void heat_pump_get_client_settings(NabtoDeviceCoapRequest* request, void* userData)
{
    HeatPump* application = (HeatPump*)userData;
    if (!heat_pump_coap_check_action(application->getFPIAM(), request, "Beta:GetClientSettings")) {
        return;
    }

    json root;
    root["ServerKey"] = application->getClientServerKey();
    root["ServerUrl"] = application->getClientServerUrl();

    auto d = json::to_cbor(root);

    nabto_device_coap_response_set_code(request, 205);
    nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, d.data(), d.size());
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 500, "Insufficient resources");
    } else {
        nabto_device_coap_response_ready(request);
    }
    nabto_device_coap_request_free(request);
}
