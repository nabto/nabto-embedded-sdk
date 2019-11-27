#pragma once

#include <nabto/nabto_device.h>

namespace nabto {
namespace test {

class AbstractCoapHandler {
 public:
    AbstractCoapHandler(NabtoDevice* device, NabtoDeviceListener* listener) : listener_(listener), device_(device)
    {
        start();
    }
    virtual ~AbstractCoapHandler() {}
    void start() {
        NabtoDeviceFuture* future = nabto_device_future_new(device_);
        nabto_device_listener_new_coap_request(listener_, future, &request_);
        nabto_device_future_set_callback(future, &AbstractCoapHandler::called, this);
    }

    static void called(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        printf("AbstractCoapHandler::called\n");
        if (ec == NABTO_DEVICE_EC_OK) {
            AbstractCoapHandler* handler = (AbstractCoapHandler*)userData;
            handler->handleRequest(handler->request_);
            handler->start();
        }
        nabto_device_future_free(future);
    }

    virtual void handleRequest(NabtoDeviceCoapRequest* request) = 0;
    NabtoDeviceListener* listener_;
    NabtoDeviceCoapRequest* request_;
    NabtoDevice* device_;
};

} } // namespace
