#pragma once

#include <nabto/nabto_device.h>

#include <future>

namespace nabto {
namespace examples {
namespace common {

class AbstractConnectionEventHandler {
 public:

    virtual void handleConnectionEvent(NabtoDeviceConnectionRef ref, NabtoDeviceConnectionEvent event) = 0;

    AbstractConnectionEventHandler(NabtoDevice* device)
        : device_(device), listener_(nabto_device_listener_new(device)), future_(nabto_device_future_new(device))
    {

    }
    virtual ~AbstractConnectionEventHandler()
    {
        stop();
        nabto_device_future_free(future_);
        nabto_device_listener_free(listener_);
    }

    bool init()
    {
        if (nabto_device_connection_events_init_listener(device_, listener_) != NABTO_DEVICE_EC_OK) {
            return false;
        }

        startListen();
        return true;
    }

    void startListen()
    {
        nabto_device_listener_connection_event(listener_, future_, &ref_, &event_);
        nabto_device_future_set_callback(future_, AbstractConnectionEventHandler::eventCallback, this);
    }

    static void eventCallback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        AbstractConnectionEventHandler* self = static_cast<AbstractConnectionEventHandler*>(userData);
        if (ec == NABTO_DEVICE_EC_OK) {
            self->handleConnectionEvent(self->ref_, self->event_);
            self->startListen();
        } else {
            self->promise_.set_value();
        }
    }

 protected:
 private:
    void stop() {
        std::future<void> future = promise_.get_future();
        nabto_device_listener_stop(listener_);
        // wait for the callback to be resolved.
        future.get();
    }
    std::promise<void> promise_;
    NabtoDevice* device_;
    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* future_;
    NabtoDeviceCoapRequest* request_;
    NabtoDeviceConnectionRef ref_;
    NabtoDeviceConnectionEvent event_;
};

} } } // namespace
