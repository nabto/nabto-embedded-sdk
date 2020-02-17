#include <nabto/nabto_device.h>

#include "coap_request_handler.hpp"

#include <nlohmann/json.hpp>

namespace nabto {
namespace fingerprint_iam {

class CoapClientSettings : public CoapRequestHandler {
 public:
    CoapClientSettings(FingerprintIAM& iam, NabtoDevice* device, const std::string& clientServerUrl, const std::string& clientServerKey)
        : CoapRequestHandler(device), iam_(iam), clientServerUrl_(clientServerUrl), clientServerKey_(clientServerKey)
    {
    }

    bool init()
    {
        return CoapRequestHandler::init(NABTO_DEVICE_COAP_GET, {"pairing", "client-settings"} );
    }

    static std::unique_ptr<CoapClientSettings> create(FingerprintIAM& iam, NabtoDevice* device, const std::string& clientServerUrl, const std::string& clientServerKey)
    {
        auto ptr = std::make_unique<CoapClientSettings>(iam, device, clientServerUrl, clientServerKey);
        ptr->init();
        return std::move(ptr);
    }

    void handleRequest(NabtoDeviceCoapRequest* request)
    {
        if (!iam_.checkAccess(nabto_device_coap_request_get_connection_ref(request), "Pairing:Get")) {
            return;
        }

        nlohmann::json root;
        root["ServerKey"] = clientServerKey_;
        root["ServerUrl"] = clientServerUrl_;

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
    std::string clientServerUrl_;
    std::string clientServerKey_;
};

} } // namespace
