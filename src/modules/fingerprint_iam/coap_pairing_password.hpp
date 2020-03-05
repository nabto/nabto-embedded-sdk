#pragma once
#include <nabto/nabto_device.h>

#include "coap_request_handler.hpp"
#include "cbor_helper.hpp"


#include <iostream>

namespace nabto {
namespace fingerprint_iam {

/**
 * This has two forms
 * Legacy
{
  "passwordstring"
}
 * New form
{
  "Password": "...",
  "Name": "..."
}
 */
class CoapPairingPassword : public CoapRequestHandler {
 public:
    CoapPairingPassword(FingerprintIAM& iam, NabtoDevice* device)
        : CoapRequestHandler(device), iam_(iam)
    {
    }

    bool init(const std::string& password)
    {
        password_ = password;
        return CoapRequestHandler::init(NABTO_DEVICE_COAP_POST, {"pairing", "password"});
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
        ec = nabto_device_connection_get_client_fingerprint_full_hex(getDevice(), ref, &fingerprint);
        if (ec) {
            nabto_device_coap_error_response(request, 500, "Server error");
            nabto_device_coap_request_free(request);
            return;
        }
        std::string clientFingerprint(fingerprint);
        nabto_device_string_free(fingerprint);

        CborParser parser;
        CborValue value;
        std::string errorDescription;

        if (!CborHelper::initCborParser(request, parser, value, errorDescription)) {
            nabto_device_coap_error_response(request, 400, errorDescription.c_str());
            nabto_device_coap_request_free(request);
            return;
        }

        std::string password;
        std::string name;

        if (!CborHelper::decodeString(value, password) &&
            !CborHelper::decodeKvString(value, "Password", password))
        {
            // The password is required either as old or in the new format.
             nabto_device_coap_error_response(request, 400, "Missing password");
             nabto_device_coap_request_free(request);
             return;
        }
        CborHelper::decodeKvString(value, "Name", name);

        if (password != password_) {
            nabto_device_coap_error_response(request, 401, "Wrong Password");
            nabto_device_coap_request_free(request);
            return;
        }

        if (!iam_.pairNewClient(request, name)) {
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
 private:
    FingerprintIAM& iam_;
    std::string password_;
};

} } // namespace
