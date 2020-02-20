#pragma once

#include "coap_request_handler.hpp"

namespace nabto {
namespace fingerprint_iam {

class CoapUsersDeleteRole : public CoapRequestHandler {
 public:
    CoapUsersDeleteRole(FingerprintIAM& iam, NabtoDevice* device)
        : CoapRequestHandler(device), iam_(iam)
    {
    }

    bool init()
    {
        return CoapRequestHandler::init(NABTO_DEVICE_COAP_DELETE, {"iam", "users", "{user}", "roles", "{role}"} );
    }

    static std::unique_ptr<CoapRequestHandler> create(FingerprintIAM& iam, NabtoDevice* device)
    {
        auto ptr = std::make_unique<CoapUsersDeleteRole>(iam, device);
        ptr->init();
        return ptr;
    }

    void handleRequest(NabtoDeviceCoapRequest* request)
    {
        const char* userId = nabto_device_coap_request_get_parameter(request, "user");
        const char* roleId = nabto_device_coap_request_get_parameter(request, "role");
        if (userId == NULL || roleId == NULL) {
            nabto_device_coap_error_response(request, 500, NULL);
            nabto_device_coap_request_free(request);
            return;
        }

        std::map<std::string, std::string> attributes;
        attributes["IAM:UserId"] = std::string(userId);
        attributes["IAM:RoleId"] = std::string(roleId);


        if (!iam_.checkAccess(nabto_device_coap_request_get_connection_ref(request), "IAM:RemoveRoleFromUser", attributes)) {
            nabto_device_coap_error_response(request, 403, "Access Denied");
            nabto_device_coap_request_free(request);
            return;
        }


        if (iam_.removeRoleFromUser(userId, roleId)) {
            nabto_device_coap_response_set_code(request, 202);
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
