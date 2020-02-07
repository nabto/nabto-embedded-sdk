#pragma once
#include <nabto/nabto_device.h>

#include "coap_request_handler.hpp"

#include <iostream>

namespace nabto {

class CoapPairingPassword : public CoapRequestHandler {
 public:
    CoapPairingPassword(FingerprintIAM& iam, NabtoDevice* device)
        : CoapRequestHandler(iam, device)
    {
    }

    bool init()
    {
        return CoapRequestHandler::init(NABTO_DEVICE_COAP_GET, {"pairing", "password"});
    }

    virtual void handleRequest(NabtoDeviceCoapRequest* request)
    {
        NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
        if (!iam_.checkAccess(ref, "Pairing:Password")) {
            nabto_device_coap_error_response(request, 403, "Access Denied");
            nabto_device_coap_request_free(request);
            return;
        }

        NabtoDeviceError ec;
        char* fingerprint;
        ec = nabto_device_connection_get_client_fingerprint_hex(getDevice(), ref, &fingerprint);
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
        bool equal;
        if (cbor_value_text_string_equals(&value, iam_.getPairingPassword().c_str(), &equal) != CborNoError) {
            nabto_device_coap_error_response(request, 400, "Bad request");
            nabto_device_coap_request_free(request);
            return;
        }

        if (!equal) {
            nabto_device_coap_error_response(request, 403, "Access denied");
            nabto_device_coap_request_free(request);
            return;
        }

        if (!iam_.pairNewClient(clientFingerprint)) {
            std::cout << "Could not pair the user" << std::endl;
            nabto_device_coap_error_response(request, 500, "Server error");
            nabto_device_coap_request_free(request);
            return;
        }

        std::cout << "Paired the user with the fingerprint " << clientFingerprint << std::endl;
        // OK response
        nabto_device_coap_response_set_code(request, 201);
        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }
};

} // namespace
