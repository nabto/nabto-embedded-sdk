#pragma once

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
    ~AbstractConnectionEventHandler()
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
        }
    }

 protected:
 private:
    void stop() {
        nabto_device_listener_stop(listener_);
        // wait until the future is no longer in use, such that we can
        // free the listener and future safely.
        nabto_device_future_wait(future_);
    }

    NabtoDevice* device_;
    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* future_;
    NabtoDeviceCoapRequest* request_;
    NabtoDeviceConnectionRef ref_;
    NabtoDeviceConnectionEvent event_;
};

} } } // namespace
