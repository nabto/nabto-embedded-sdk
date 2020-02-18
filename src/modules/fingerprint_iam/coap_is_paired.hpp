#include <nabto/nabto_device.h>

#include "coap_request_handler.hpp"

namespace nabto {
namespace fingerprint_iam {

class CoapIsPaired : public CoapRequestHandler {
 public:
    CoapIsPaired(FingerprintIAM& iam, NabtoDevice* device)
        : CoapRequestHandler(device), iam_(iam)
    {
    }

    bool init()
    {
        return CoapRequestHandler::init(NABTO_DEVICE_COAP_GET, {"pairing", "is-paired"} );
    }

    static std::unique_ptr<CoapIsPaired> create(FingerprintIAM& iam, NabtoDevice* device)
    {
        auto ptr = std::make_unique<CoapIsPaired>(iam, device);
        ptr->init();
        return ptr;
    }

    void handleRequest(NabtoDeviceCoapRequest* request)
    {
        NabtoDeviceConnectionRef ref = nabto_device_coap_request_get_connection_ref(request);
        if (!iam_.checkAccess(ref, "Pairing:Get")) {
            nabto_device_coap_error_response(request, 403, "Access Denied");
            nabto_device_coap_request_free(request);
            return;
        }

        NabtoDeviceError ec;
        char* fingerprint;
        ec = nabto_device_connection_get_client_fingerprint_hex(device_, ref, &fingerprint);
        if (ec) {
            nabto_device_coap_error_response(request, 500, "Server error");
            nabto_device_coap_request_free(request);
            return;
        }

        std::string clientFingerprint(fingerprint);
        nabto_device_string_free(fingerprint);

        if (iam_.isPaired(clientFingerprint)) {
            nabto_device_coap_response_set_code(request, 205);
        } else {
            nabto_device_coap_response_set_code(request, 403);
        }

        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }
 private:
    FingerprintIAM& iam_;
};

} } // namespace
