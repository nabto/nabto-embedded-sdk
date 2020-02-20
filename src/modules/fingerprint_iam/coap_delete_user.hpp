#pragma once

#include "coap_request_handler.hpp"

namespace nabto {
namespace fingerprint_iam {

class CoapDeleteUser : public CoapRequestHandler {
 public:
    CoapDeleteUser(FingerprintIAM& iam, NabtoDevice* device)
        : CoapRequestHandler(device), iam_(iam)
    {
    }

    bool init()
    {
        return CoapRequestHandler::init(NABTO_DEVICE_COAP_DELETE, {"iam", "users", "{id}"} );
    }

    static std::unique_ptr<CoapDeleteUser> create(FingerprintIAM& iam, NabtoDevice* device)
    {
        auto ptr = std::make_unique<CoapDeleteUser>(iam, device);
        ptr->init();
        return ptr;
    }

    void handleRequest(NabtoDeviceCoapRequest* request)
    {
        const char* userId = nabto_device_coap_request_get_parameter(request, "id");
        if (userId == NULL) {
            nabto_device_coap_error_response(request, 500, NULL);
            nabto_device_coap_request_free(request);
            return;
        }

        std::map<std::string, std::string> attributes;
        attributes["IAM:UserId"] = std::string(userId);

        if (!iam_.checkAccess(nabto_device_coap_request_get_connection_ref(request), "IAM:DeleteUser")) {
            nabto_device_coap_error_response(request, 403, "Access Denied");
            nabto_device_coap_request_free(request);
            return;
        }

        iam_.deleteUser(userId);

        nabto_device_coap_response_set_code(request, 202);
        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }

 private:
    FingerprintIAM& iam_;
};

} } // namespace
