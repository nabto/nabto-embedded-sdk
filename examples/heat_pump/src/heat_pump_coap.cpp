#include "heat_pump_coap.hpp"
#include "heat_pump.hpp"
#include "nabto/nabto_device.h"
#include "nabto/nabto_device_experimental.h"

#include <cjson/cJSON.h>

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

void heat_pump_coap_init(NabtoDevice* device, HeatPump* heatPump)
{
    const char* getState[] = { "heat-pump", NULL };
    const char* postPower[] = { "heat-pump", "power", NULL };
    const char* postMode[] = { "heat-pump", "mode", NULL };
    const char* postTarget[] = { "heat-pump", "target", NULL };
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_GET, getState, heat_pump_get, heatPump);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_POST, postPower, heat_pump_set_power, heatPump);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_POST, postMode, heat_pump_set_mode, heatPump);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_POST, postTarget, heat_pump_set_target, heatPump);
}


void heat_pump_coap_send_error(NabtoDeviceCoapRequest* request, uint16_t code, const char* message)
{
     NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
     nabto_device_coap_response_set_code(response, code);
     nabto_device_coap_response_set_content_format(response, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
     nabto_device_coap_response_set_payload(response, message, strlen(message));
     nabto_device_coap_response_ready(response);
}

void heat_pump_coap_send_bad_request(NabtoDeviceCoapRequest* request)
{
    heat_pump_coap_send_error(request, 400, "Bad request");
}

void heat_pump_coap_send_ok(NabtoDeviceCoapRequest* request, uint16_t code)
{
     NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
     nabto_device_coap_response_set_code(response, code);
     nabto_device_coap_response_ready(response);
}

// return true if action was allowed
bool heat_pump_coap_check_action(NabtoDeviceCoapRequest* request, const char* action)
{
    NabtoDeviceIamEnv* iamEnv = nabto_device_iam_env_from_coap_request(request);
    NabtoDeviceError effect = nabto_device_iam_check_action(iamEnv, action);
    if (effect == NABTO_DEVICE_EC_OK) {
        return true;
    } else {
        // deny
        heat_pump_coap_send_error(request, 403, "Unauthorized");
        return false;
    }
}

bool heat_pump_init_cbor_parser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue)
{
    uint16_t contentFormat;
    NabtoDeviceError ec;
    ec = nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (ec || contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR) {
        heat_pump_coap_send_error(request, 400, "Invalid Content Format");
        return false;
    }
    void* payload;
    size_t payloadSize;
    if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
        heat_pump_coap_send_error(request, 400, "Missing payload");
        return false;
    }
    cbor_parser_init((const uint8_t*)payload, payloadSize, 0, parser, 0);
    return true;
}

std::condition_variable cv;
bool answer;

void readInput()
{
    for(;;) {
        char c;
        std::cin >> c;
        if (c == 'n') {
            answer = false;
            cv.notify_one();
        } else if (c == 'y') {
            answer = true;
            cv.notify_one();
        } else {
            std::cout << "valid answers y or n" << std::endl;
        }
    }

}

void questionHandler(NabtoDeviceCoapRequest* request, HeatPump* application)
{
    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
    char* fingerprint;
    nabto_device_connection_get_client_fingerprint_hex(application->getDevice(), ref, &fingerprint);
    std::cout << "Allow client with fingerprint: " << std::string(fingerprint) << " [yn]" << std::endl;

    std::thread t(readInput);
    std::mutex mtx;
    std::unique_lock<std::mutex> lock(mtx);
    bool result = false;
    if (cv.wait_for(lock, std::chrono::seconds(60)) == std::cv_status::timeout) {
        std::cout << "No input given defaulting to n" << std::endl;
    } else {
        result = answer;
    }
    t.join();

    if (result == true) {
        auto response = nabto_device_coap_create_response(request);
        nabto_device_coap_response_set_code(response, 205);
        nabto_device_coap_response_ready(response);
    } else {
        nabto_device_coap_error_response(request, 403, "Rejected");
    }
    application->pairingEnded();
}

/**
 * Pair with a device.
 *
 * The pairing asks the user for a confirmation that the client in
 * question is allowed to pair with the device. This simulates a
 * button on the device.
 */
void heat_pump_coap_pair(NabtoDeviceCoapRequest* request, void* userData)
{
    HeatPump* application = (HeatPump*)userData;

    if (!application->beginPairing()) {
        nabto_device_coap_error_response(request, 403, "Already Pairing or paired");
    }

    std::thread t(questionHandler, request, application);
    t.detach();

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

    if (!heat_pump_coap_check_action(request, "heat_pump:SetPower")) {
        return;
    }

    CborParser parser;
    CborValue value;
    if (!heat_pump_init_cbor_parser(request, &parser, &value)) {
        return;
    }

    bool powerState;
    if (!cbor_value_is_boolean(&value) || !cbor_value_get_boolean(&value, &powerState)) {
        heat_pump_coap_send_error(request, 400, "Invalid request");
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
    if (!heat_pump_coap_check_action(request, "heat_pump:SetMode")) {
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

    if (cbor_value_text_string_equals(&value, cool, &match) && match) {
        application->setMode(HeatPump::Mode::COOL);
    } else if (cbor_value_text_string_equals(&value, heat, &match) && match) {
        application->setMode(HeatPump::Mode::HEAT);
    } else if (cbor_value_text_string_equals(&value, fan, &match) && match) {
        application->setMode(HeatPump::Mode::FAN);
    } else if (cbor_value_text_string_equals(&value, dry, &match) && match) {
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
    if (!heat_pump_coap_check_action(request, "heat_pump:SetTarget")) {
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
    if (!cbor_value_get_floating_point(&value, &target)) {
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
    if (!heat_pump_coap_check_action(request, "heat_pump:GetState")) {
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
        return heat_pump_coap_send_error(request, 500, "Internal error");
    }

    NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
    nabto_device_coap_response_set_code(response, 200);
    nabto_device_coap_response_set_content_format(response, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_device_coap_response_set_payload(response, buffer, cbor_encoder_get_buffer_size(&encoder, buffer));
    nabto_device_coap_response_ready(response);
}
