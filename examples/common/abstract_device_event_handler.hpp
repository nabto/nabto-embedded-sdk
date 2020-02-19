#pragma once

namespace nabto {
namespace examples {
namespace common {

class AbstractDeviceEventHandler {
 public:

    virtual void handleDeviceEvent(NabtoDeviceEvent event) = 0;

    AbstractDeviceEventHandler(NabtoDevice* device)
        : device_(device), listener_(nabto_device_listener_new(device)), future_(nabto_device_future_new(device))
    {
    }

    virtual ~AbstractDeviceEventHandler()
    {
        stop();
        nabto_device_future_free(future_);
        nabto_device_listener_free(listener_);
    }

    bool init()
    {
        if (nabto_device_device_events_init_listener(device_, listener_) != NABTO_DEVICE_EC_OK) {
            return false;
        }

        startListen();
        return true;
    }

    void startListen()
    {
        nabto_device_listener_device_event(listener_, future_, &event_);
        nabto_device_future_set_callback(future_, AbstractDeviceEventHandler::eventCallback, this);
    }

    static void eventCallback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
    {
        AbstractDeviceEventHandler* self = static_cast<AbstractDeviceEventHandler*>(userData);
        if (ec == NABTO_DEVICE_EC_OK) {
            self->handleDeviceEvent(self->event_);
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

        // wait for listener to be stopped
        future.get();
    }

    std::promise<void> promise_;
    NabtoDevice* device_;
    NabtoDeviceListener* listener_;
    NabtoDeviceFuture* future_;
    NabtoDeviceEvent event_;
};

} } } // namespace
