#pragma once

#include "fingerprint_iam.hpp"

#include <modules/iam_cpp/attributes.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <future>

namespace nabto {
namespace fingerprint_iam {

class AuthorizationRequestHandler {
 public:
    AuthorizationRequestHandler(NabtoDevice* device, FingerprintIAM& fingerprintIAM)
        : device_(device), fingerprintIAM_(fingerprintIAM),
          listener_(nabto_device_listener_new(device)), future_(nabto_device_future_new(device))
    {
    }
    ~AuthorizationRequestHandler()
    {
        stop();
        nabto_device_future_free(future_);
        nabto_device_listener_free(listener_);
    }

    static std::unique_ptr<AuthorizationRequestHandler> create(NabtoDevice* device, FingerprintIAM& fingerprintIAM)
    {
        auto ptr = std::make_unique<AuthorizationRequestHandler>(device, fingerprintIAM);
        ptr->init();
        return ptr;
    }

    bool init()
    {
        if (nabto_device_authorization_request_init_listener(device_, listener_) != NABTO_DEVICE_EC_OK) {
            return false;
        }

        startListen();
        return true;
    }

    void startListen()
    {
        nabto_device_listener_new_authorization_request(listener_, future_, &event_);
        nabto_device_future_set_callback(future_, AuthorizationRequestHandler::authorizationRequestCallback, this);
    }

    static void authorizationRequestCallback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        AuthorizationRequestHandler* self = static_cast<AuthorizationRequestHandler*>(userData);
        if (ec == NABTO_DEVICE_EC_OK) {
            self->handleAuthorizationRequest(self->event_);
            self->startListen();
        } else {
            self->promise_.set_value();
        }
    }

    void handleAuthorizationRequest(NabtoDeviceAuthorizationRequest* request)
    {
        std::string action(nabto_device_authorization_request_get_action(request));
        nabto::iam::AttributeMap attributes;

        size_t nAttributes = nabto_device_authorization_request_get_attributes_size(request);
        for (size_t i = 0; i < nAttributes; i++) {
            std::string name(nabto_device_authorization_request_get_attribute_name(request, i));
            std::string value(nabto_device_authorization_request_get_attribute_value(request, i));
            attributes[name] = value;
        }
        NabtoDeviceConnectionRef ref = nabto_device_authorization_request_get_connection_ref(request);
        bool verdict = fingerprintIAM_.checkAccess(ref, action, iam::Attributes(attributes));
        nabto_device_authorization_request_verdict(request, verdict);
        nabto_device_authorization_request_free(request);
    }

 private:

    void stop() {
        std::future<void> future = promise_.get_future();
        nabto_device_listener_stop(listener_);

        // wait for listener to be stopped
        future.get();
    }

    NabtoDevice* device_;
    FingerprintIAM& fingerprintIAM_;
    std::promise<void> promise_;

    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* future_;
    NabtoDeviceAuthorizationRequest* event_;
};

} } // namespace
