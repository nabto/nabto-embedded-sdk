#pragma once

#include <nabto/nabto_device.h>

#include <cbor.h>

#include <future>

namespace nabto {
namespace fingerprint_iam {

class CoapRequestHandler {
 public:
    CoapRequestHandler(NabtoDevice* device)
        : device_(device), listener_(nabto_device_listener_new(device)), future_(nabto_device_future_new(device))
    {

    }
    virtual ~CoapRequestHandler()
    {
        stop();
        nabto_device_future_free(future_);
        nabto_device_listener_free(listener_);
    }

    bool init(NabtoDeviceCoapMethod method, const std::vector<std::string>& segments)
    {
        std::vector<const char*> paths;

        for (auto& s : segments) {
            paths.push_back(s.c_str());
        }
        paths.push_back(NULL);

        if (nabto_device_coap_init_listener(device_, listener_, method, paths.data()) != NABTO_DEVICE_EC_OK) {
            return false;
        }

        startListen();
        return true;
    }

    void startListen()
    {
        nabto_device_listener_new_coap_request(listener_, future_, &request_);
        nabto_device_future_set_callback(future_, CoapRequestHandler::requestCallback, this);
    }

    static void requestCallback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        CoapRequestHandler* self = static_cast<CoapRequestHandler*>(userData);
        if (ec == NABTO_DEVICE_EC_OK) {
            self->handleRequest(self->request_);
            self->startListen();
        } else {
            self->promise_.set_value();
        }
    }
    virtual void handleRequest(NabtoDeviceCoapRequest* request) = 0;

    NabtoDevice* getDevice() {
        return device_;
    }
 protected:

    void stop()
    {
        std::future<void> future = promise_.get_future();
        nabto_device_listener_stop(listener_);

        // wait for the listener to be stopped
        future.get();
    }

    std::promise<void> promise_;

    NabtoDevice* device_;
    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* future_;
    NabtoDeviceCoapRequest* request_;
};

} } // namespace
