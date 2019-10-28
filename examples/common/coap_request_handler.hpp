#pragma once

#include <functional>
#include <nabto/nabto_device.h>

namespace nabto {
namespace common {

typedef std::function<void (NabtoDeviceCoapRequest* request, void* application)> CoapHandler;

class CoapRequestHandler {
 public:
    ~CoapRequestHandler() {
        nabto_device_listener_free(listener_);
        nabto_device_future_free(future_);
    }
    CoapRequestHandler(void* application, NabtoDevice* device, NabtoDeviceCoapMethod methdod, const char** pathSegments, CoapHandler handler);

    void startListen();
    void stopListen()
    {
        nabto_device_listener_stop(listener_);
    }

    static void requestCallback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        CoapRequestHandler* handler = (CoapRequestHandler*)data;
        if (ec != NABTO_DEVICE_EC_OK) {
            return;
        }
        handler->handler_(handler->request_, handler->application_);
        handler->startListen();
    }

    void* application_;
    //  wait for a request
    NabtoDeviceFuture* future_;
    NabtoDeviceCoapRequest* request_;
    // on this listener
    NabtoDeviceListener* listener_;
    // invoke this function if the resource is hit
    CoapHandler handler_;
};

} } // namespace
