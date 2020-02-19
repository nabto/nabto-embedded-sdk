#pragma once
#include <nabto/nabto_device.h>

#include "coap_request_handler.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

namespace nabto {
namespace fingerprint_iam {

class CoapPairing : public CoapRequestHandler {
 public:
    CoapPairing(FingerprintIAM& iam, NabtoDevice* device)
        : CoapRequestHandler(device), iam_(iam)
    {
    }

    bool init()
    {
        return CoapRequestHandler::init(NABTO_DEVICE_COAP_GET, {"pairing"});
    }

    static std::unique_ptr<CoapPairing> create(FingerprintIAM& iam, NabtoDevice* device)
    {
        auto ptr = std::make_unique<CoapPairing>(iam, device);
        ptr->init();
        return ptr;
    }

    /**
     * Return public state of the pairing module.
     */
    virtual void handleRequest(NabtoDeviceCoapRequest* request)
    {
        NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
        if (!iam_.checkAccess(ref, "Pairing:Get")) {
            nabto_device_coap_error_response(request, 403, "Access Denied");
            nabto_device_coap_request_free(request);
            return;
        }

        nlohmann::json state;

        state["Modes"] = iam_.getPairingModes();

        auto d = nlohmann::json::to_cbor(state);

        nabto_device_coap_response_set_code(request, 205);
        nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        nabto_device_coap_response_set_payload(request, d.data(), d.size());
        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }
 private:
    FingerprintIAM& iam_;
};

} } // namespace
