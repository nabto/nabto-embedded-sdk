#pragma once

#include "coap_request_handler.hpp"

namespace nabto {
namespace fingerprint_iam {

class CoapListRoles : public CoapRequestHandler {
 public:
    CoapListRoles(FingerprintIAM& iam, NabtoDevice* device)
        : CoapRequestHandler(device), iam_(iam)
    {
    }

    bool init()
    {
        return CoapRequestHandler::init(NABTO_DEVICE_COAP_GET, {"iam", "roles"} );
    }

    static std::unique_ptr<CoapRequestHandler> create(FingerprintIAM& iam, NabtoDevice* device)
    {
        auto ptr = std::make_unique<CoapListRoles>(iam, device);
        ptr->init();
        return ptr;
    }

    void handleRequest(NabtoDeviceCoapRequest* request)
    {
        if (!iam_.checkAccess(nabto_device_coap_request_get_connection_ref(request), "IAM:ListRoles")) {
            nabto_device_coap_error_response(request, 403, "Access Denied");
            nabto_device_coap_request_free(request);
            return;
        }

        nlohmann::json root = nlohmann::json::array();
        for (auto r : iam_.getRoles()) {
            root.push_back(r->getId());
        }

        auto d = nlohmann::json::to_cbor(root);

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

 private:
    FingerprintIAM& iam_;
};

} } // namespace
