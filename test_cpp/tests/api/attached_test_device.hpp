#pragma once

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <future>

namespace nabto {
namespace test {

class AttachedTestDevice {
 public:
    AttachedTestDevice() {
        device_ = nabto_device_new();
        future_ = nabto_device_future_new(device_);
        eventFuture_ = nabto_device_future_new(device_);
        eventListener_ = nabto_device_listener_new(device_);

        nabto_device_set_product_id(device_, productId_.c_str());
        nabto_device_set_device_id(device_, deviceId_.c_str());
        char* pk;
        nabto_device_create_private_key(device_, &pk);
        nabto_device_set_private_key(device_, pk);
        nabto_device_string_free(pk);

        nabto_device_set_local_port(device_, 0);
        nabto_device_set_p2p_port(device_, 0);

        const char* logLevel = getenv("NABTO_LOG_LEVEL");
        if (logLevel != NULL) {
            nabto_device_set_log_level(device_, logLevel);
            nabto_device_set_log_std_out_callback(device_);
        }

    }

    ~AttachedTestDevice() {
        nabto_device_stop(device_);
        nabto_device_listener_free(eventListener_);
        nabto_device_future_free(future_);
        nabto_device_future_free(eventFuture_);
        nabto_device_free(device_);
    }

    NabtoDeviceError attach(const std::string& hostname, uint16_t port, const std::string& rcs)
    {
        nabto_device_set_server_url(device_, hostname.c_str());
        nabto_device_set_server_port(device_, port);
        nabto_device_set_root_certs(device_, rcs.c_str());
        listenForEvents();
        nabto_device_start(device_, future_);

        BOOST_TEST(EC(nabto_device_future_wait(future_)) == EC(NABTO_DEVICE_EC_OK));
        // start the device and wait for it ot be attached to the basestation

        std::future<void> f = isAttached_.get_future();
        f.get();
        return NABTO_DEVICE_EC_OK;
    }


    NabtoDeviceError noAttach()
    {
        nabto_device_set_basestation_attach(device_, false);
        listenForEvents();
        nabto_device_start(device_, future_);

        BOOST_TEST(EC(nabto_device_future_wait(future_)) == EC(NABTO_DEVICE_EC_OK));
        // start the device and wait for it ot be attached to the basestation
        return NABTO_DEVICE_EC_OK;
    }

    void waitForAttached()
    {
        std::future<void> f = isAttached_.get_future();
        f.get();
    }

    void listenForEvents() {
        nabto_device_device_events_init_listener(device_, eventListener_);
        startGetEvent();
    }

    void startGetEvent() {
        nabto_device_listener_device_event(eventListener_, eventFuture_, &event_);
        nabto_device_future_set_callback(eventFuture_, AttachedTestDevice::newEvent, this);
    }

    static void newEvent(NabtoDeviceFuture* future, NabtoDeviceError ec, void* data) {
        (void)future;
        AttachedTestDevice* device = (AttachedTestDevice*)(data);
        if (ec != NABTO_DEVICE_EC_OK) {
            return;
        }
        if (device->event_ == NABTO_DEVICE_EVENT_ATTACHED) {
            device->isAttached_.set_value();
        }
        device->startGetEvent();
    }
    NabtoDevice* device() {
        return device_;
    }

    void stop() {
        nabto_device_stop(device_);
    }

 private:
    NabtoDevice* device_;
    NabtoDeviceFuture* future_;
    NabtoDeviceListener* eventListener_;
    NabtoDeviceFuture* eventFuture_;
    NabtoDeviceEvent event_;
    std::string productId_ = "pr-12345678";
    std::string deviceId_ = "de-abcdefgh";
    std::promise<void> isAttached_;
};

} } // namespace
