#include "fingerprint_iam_coap.hpp"

#include <cbor.h>

namespace nabto {

static bool initCborParser(NabtoDeviceCoapRequest* request, CborParser* parser, CborValue* cborValue)
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

void FingerprintIamCoap::handlePasswordPairing(NabtoDeviceCoapRequest* request)
{
    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
    if (!fiam->checkAccess(ref, "Pairing:Password")) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        nabto_device_coap_request_free(request);
        return;
    }

    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint_hex(application->getDevice(), ref, &fingerprint);
    if (ec) {
        nabto_device_coap_error_response(request, 500, "Server error");
        nabto_device_coap_request_free(request);
        return;
    }
    std::string clientFingerprint(fingerprint);
    nabto_device_string_free(fingerprint);

    CborParser parser;
    CborValue value;
    if (!initCborParser(request, &parser, &value)) {
        return;
    }
    if (!cbor_value_is_text_string(&value)) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        nabto_device_coap_request_free(request);
        return;
    }
    if (cbor_value_text_string_equals(&value, application->getPairingPassword().c_str(), &equal) != CborNoError) {
        nabto_device_coap_error_response(request, 400, "Bad request");
        nabto_device_coap_request_free(request);
        return;
    }

    if (!equal) {
        nabto_device_coap_error_response(request, 403, "Access denied");
        nabto_device_coap_request_free(request);
        return;
    }

    if (!fiam->pairNewClient(clientFingerprint)) {
        std::cout << "Could not pair the user" << std::endl;
        nabto_device_coap_error_response(request, 500, "Server error");
        nabto_device_coap_request_free(request);
        return;
    }

    std::cout << "Paired the user with the fingerprint " << fp << std::endl;
    // OK response
    nabto_device_coap_response_set_code(request, 201);
    nabto_device_coap_response_ready(request);
    nabto_device_coap_request_free(request);
}

void FingerprintIamCoap::handleIsPaired(NabtoDeviceCoapRequest* request)
{
    NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
    if (!fiam->checkAccess(ref, "Pairing:IsPaired")) {
        nabto_device_coap_error_response(request, 403, "Access Denied");
        nabto_device_coap_request_free(request);
        return;
    }

    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint_hex(application->getDevice(), ref, &fingerprint);
    if (ec) {
        nabto_device_coap_error_response(request, 500, "Server error");
        nabto_device_coap_request_free(request);
        return;
    }

    std::string clientFingerprint(fingerprint);
    nabto_device_string_free(fingerprint);

    if (fiam->isPaired()) {
        nabto_device_coap_response_set_code(request, 205);
    } else {
        nabto_device_coap_response_set_code(request, 403);
    }

    nabto_device_coap_response_ready(request);
    nabto_device_coap_request_free(request);
}

} // namespace
