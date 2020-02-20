#pragma once

#include "coap_request_handler.hpp"

namespace nabto {
namespace fingerprint_iam {

class CoapUsersAddRole : public CoapRequestHandler {
 public:
    CoapUsersAddRole(FingerprintIAM& iam, NabtoDevice* device)
        : CoapRequestHandler(device), iam_(iam)
    {
    }

    bool init()
    {
        return CoapRequestHandler::init(NABTO_DEVICE_COAP_PUT, {"iam", "users", "{id}", "roles", "{role}"} );
    }

    static std::unique_ptr<CoapRequestHandler> create(FingerprintIAM& iam, NabtoDevice* device)
    {
        auto ptr = std::make_unique<CoapUsersAddRole>(iam, device);
        ptr->init();
        return ptr;
    }

    void handleRequest(NabtoDeviceCoapRequest* request)
    {
        if (!iam_.checkAccess(nabto_device_coap_request_get_connection_ref(request), "IAM:AddUserRole")) {
            nabto_device_coap_error_response(request, 403, "Access Denied");
            nabto_device_coap_request_free(request);
            return;
        }

        const char* userId = nabto_device_coap_request_get_parameter(request, "id");
        const char* roleId = nabto_device_coap_request_get_parameter(request, "role");
        if (userId == NULL || roleId == NULL) {
            nabto_device_coap_error_response(request, 500, NULL);
            nabto_device_coap_request_free(request);
            return;
        }

        if (iam_.addRoleToUser(userId, roleId)) {
            nabto_device_coap_response_set_code(request, 201);
        } else {
            nabto_device_coap_response_set_code(request, 404);
        }
        nabto_device_coap_response_ready(request);
        nabto_device_coap_request_free(request);
    }

 private:
    FingerprintIAM& iam_;
};

} } // namespace
