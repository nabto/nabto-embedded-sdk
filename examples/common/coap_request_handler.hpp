#pragma once

#include <functional>
#include <nabto/nabto_device.h>

namespace nabto {
namespace common {

typedef std::function<void (NabtoDeviceCoapRequest* request, void* application)> CoapHandler;

class CoapRequestHandler {
 public:
    ~CoapRequestHandler() {}
    CoapRequestHandler(void* application, NabtoDevice* device, NabtoDeviceCoapMethod methdod, const char** pathSegments, CoapHandler handler);

    void startListen();

    static void requestCallback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
    {
        nabto_device_future_free(fut);
        if (ec != NABTO_DEVICE_EC_OK) {
            return;
        }
        CoapRequestHandler* handler = (CoapRequestHandler*)data;
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
