#include "heat_pump_coap.hpp"
#include "heat_pump.hpp"
#include "nabto/nabto_device.h"
#include "nabto/nabto_device_experimental.h"

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

void heat_pump_coap_init(NabtoDevice* device, HeatPump* heatPump)
{
    const char* getState[] = { "heat-pump", NULL };
    const char* postPower[] = { "heat-pump", "power", NULL };
    const char* postMode[] = { "heat-pump", "mode", NULL };
    const char* postTarget[] = { "heat-pump", "target", NULL };
    const char* postPairingButton[] = { "pairing", "button", NULL };
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_GET, getState, heat_pump_get, heatPump);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_POST, postPower, heat_pump_set_power, heatPump);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_POST, postMode, heat_pump_set_mode, heatPump);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_POST, postTarget, heat_pump_set_target, heatPump);
    nabto_device_coap_add_resource(device, NABTO_DEVICE_COAP_POST, postPairingButton, heat_pump_pairing_button, heatPump);
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
bool heat_pump_coap_check_action(NabtoDevice* device, NabtoDeviceCoapRequest* request, const char* action)
{
    NabtoDeviceError effect = nabto_device_iam_check_action_attributes(
        device,
        nabto_device_coap_request_get_connection_ref(request), action, NULL, 0);

    if (effect != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 403, "Unauthorized");
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
        heat_pump_coap_send_error(request, 400, "Invalid Content Format");
        return false;
    }
    void* payload;
    size_t payloadSize;
    if (nabto_device_coap_request_get_payload(request, &payload, &payloadSize) != NABTO_DEVICE_EC_OK) {
        heat_pump_coap_send_error(request, 400, "Missing payload");
        return false;
    }
    cbor_parser_init((const uint8_t*)payload, payloadSize, 0, parser, cborValue);
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
            return;
        } else if (c == 'y') {
            answer = true;
            cv.notify_one();
            return;
        } else {
            std::cout << "valid answers y or n" << std::endl;
        }
    }

}

bool pairUser( HeatPump* application, const std::string& fingerprint)
{
    std::string userName;
    size_t userCount;
    NabtoDeviceError ec;
    ec = application->nextUserName(userName);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }

    ec = application->userCount(userCount);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }

    ec = nabto_device_iam_users_create(application->getDevice(), userName.c_str());
    if (ec) {
        return false;
    }

    ec = nabto_device_iam_users_add_fingerprint(application->getDevice(), userName.c_str(), fingerprint.c_str());
    if (ec) {
        nabto_device_iam_users_delete(application->getDevice(), userName.c_str());
        std::cout << "Could not add fingerprint to the heat pump" << std::endl;
        return false;
    }

    std::string role;
    if (userCount == 0) {
        role = "Owner";
    } else {
        role = "User";
    }
    ec = nabto_device_iam_users_add_role(application->getDevice(), userName.c_str(), role.c_str());
    if (ec) {
        nabto_device_iam_users_delete(application->getDevice(), userName.c_str());
        std::cout << "Could not add the role " << role.c_str() << " to the user " << userName << std::endl;
        return false;
    }
    std::cout << "Added the fingerprint " << fingerprint << " to the user " << userName << " with the role " << role<< std::endl;
    return true;
}

void questionHandler(NabtoDeviceCoapRequest* request, HeatPump* application, bool asOwner)
{
    if (!application->beginPairing()) {
        nabto_device_coap_error_response(request, 403, "Already Pairing or paired");
        return;
    }
    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
    char* fingerprint;
    nabto_device_connection_get_client_fingerprint_hex(application->getDevice(), ref, &fingerprint);

    std::cout << "Allow client with fingerprint: " << std::string(fingerprint) << " [yn]" << std::endl;

    std::thread t(readInput);
    t.detach();
    std::mutex mtx;
    std::unique_lock<std::mutex> lock(mtx);
    bool result = false;
    if (cv.wait_for(lock, std::chrono::seconds(60)) == std::cv_status::timeout) {
        std::cout << "No input given defaulting to n" << std::endl;
    } else {
        result = answer;
    }

    if (result == true && pairUser(application, std::string(fingerprint))) {
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
void heat_pump_pairing_button(NabtoDeviceCoapRequest* request, void* userData)
{
    HeatPump* application = (HeatPump*)userData;

    size_t userCount;
    NabtoDeviceError ec = application->userCount(userCount);
    if (ec) {
        nabto_device_coap_error_response(request, 500, "");
        return;
    }

    json attributes;
    attributes["Pairing:UserCount"] = userCount;

    std::vector<uint8_t> cbor = json::to_cbor(attributes);

    NabtoDeviceError effect = nabto_device_iam_check_action_attributes(
        application->getDevice(),
        nabto_device_coap_request_get_connection_ref(request), "Pairing:Button", cbor.data(), cbor.size());

    if (effect != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 403, "Unauthorized");
        return;
    }

    application->pairingThread_ = std::make_unique<std::thread>(questionHandler, request, application, true);
    application->pairingThread_->detach();
}

void heat_pump_pairing_button_guest(NabtoDeviceCoapRequest* request, void* userData)
{
    HeatPump* application = (HeatPump*)userData;

    NabtoDeviceError effect = nabto_device_iam_check_action(
        application->getDevice(),
        nabto_device_coap_request_get_connection_ref(request), "Pairing:ButtonGuest");

    if (effect != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 403, "Unauthorized");
        return;
    }

    application->pairingThread_ = std::make_unique<std::thread>(questionHandler, request, application, false);
    application->pairingThread_->detach();
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

    if (!heat_pump_coap_check_action(application->getDevice(), request, "HeatPump:Set")) {
        return;
    }

    CborParser parser;
    CborValue value;
    if (!heat_pump_init_cbor_parser(request, &parser, &value)) {
        return;
    }

    bool powerState;
    if (!cbor_value_is_boolean(&value) || cbor_value_get_boolean(&value, &powerState) != CborNoError) {
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
    if (!heat_pump_coap_check_action(application->getDevice(), request, "HeatPump:Set")) {
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
    if (!heat_pump_coap_check_action(application->getDevice(), request, "HeatPump:Set")) {
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
    if (!heat_pump_coap_check_action(application->getDevice(), request, "HeatPump:Get")) {
        return;
    }

    auto d = json::to_cbor(application->getState());

    NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
    nabto_device_coap_response_set_code(response, 205);
    nabto_device_coap_response_set_content_format(response, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
    nabto_device_coap_response_set_payload(response, d.data(), d.size());
    nabto_device_coap_response_ready(response);
}
