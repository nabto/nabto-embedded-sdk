#include <boost/test/unit_test.hpp>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "../../util/helper.hpp"
#include "../attach/attach_server.hpp"
#include "../../util/io_service.hpp"

#include <thread>
#include <future>

namespace {

class FcmTestDevice {
 public:
    FcmTestDevice() {
        device_ = nabto_device_new();
        future_ = nabto_device_future_new(device_);
        eventFuture_ = nabto_device_future_new(device_);
        eventListener_ = nabto_device_listener_new(device_);

        nabto_device_set_product_id(device_, productId_.c_str());
        nabto_device_set_device_id(device_, deviceId_.c_str());
        char* privateKey;
        nabto_device_create_private_key(device_, &privateKey);
        nabto_device_set_private_key(device_, privateKey);
        nabto_device_string_free(privateKey);

        nabto_device_set_local_port(device_, 0);
        nabto_device_set_p2p_port(device_, 0);

        const char* logLevel = getenv("NABTO_LOG_LEVEL");
        if (logLevel != NULL) {
            nabto_device_set_log_level(device_, logLevel);
            nabto_device_set_log_std_out_callback(device_);
        }

    }

    ~FcmTestDevice() {
        nabto_device_stop(device_);
        nabto_device_listener_free(eventListener_);
        nabto_device_future_free(future_);
        nabto_device_future_free(eventFuture_);
        nabto_device_free(device_);
    }

    NabtoDeviceError attach(const std::string& hostname, uint16_t port, const std::string& rootCerts) 
    {
        nabto_device_set_server_url(device_, hostname.c_str());
        nabto_device_set_server_port(device_, port);
        nabto_device_set_root_certs(device_, rootCerts.c_str());
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
        nabto_device_set_server_url(device_, "localhost");
        nabto_device_set_server_port(device_, 4242);
        listenForEvents();
        nabto_device_start(device_, future_);

        BOOST_TEST(EC(nabto_device_future_wait(future_)) == EC(NABTO_DEVICE_EC_OK));
        // start the device and wait for it ot be attached to the basestation
        return NABTO_DEVICE_EC_OK;
    }
    

    void listenForEvents() {
        nabto_device_device_events_init_listener(device_, eventListener_);
        startGetEvent();
    }

    void startGetEvent() {
        nabto_device_listener_device_event(eventListener_, eventFuture_, &event_);
        nabto_device_future_set_callback(eventFuture_, FcmTestDevice::newEvent, this);
    }

    static void newEvent(NabtoDeviceFuture* future, NabtoDeviceError ec, void* data) {
        FcmTestDevice* device = (FcmTestDevice*)(data);
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

class BasestationFixture {
 public:
    BasestationFixture() 
        : ioService_(nabto::IoService::create("basestationFixture")), attachServer_(nabto::test::AttachServer::create(ioService_->getIoService()))
    {
    }
    ~BasestationFixture()  
    {
        attachServer_->stop();
    }
    std::string getRootCerts() {
        return attachServer_->getRootCerts();
    }
    std::string getHostname() {
        return attachServer_->getHostname();
    }
    uint16_t getPort() {
        return attachServer_->getPort();
    }
 private:
    nabto::IoServicePtr ioService_;
    std::shared_ptr<nabto::test::AttachServer> attachServer_;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(fcm, BasestationFixture)

BOOST_AUTO_TEST_CASE(create_destroy_notification)
{
    NabtoDevice* dev = nabto_device_new();

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    nabto_device_fcm_notification_free(n);
    nabto_device_free(dev);
}

std::string testFcmPayload = R"(
{
    "message":{
        "notification": {
            "title": "foo",
            "body": "bar"
        },
        "token": "abcdef"
    }
}
)";

BOOST_AUTO_TEST_CASE(notification_set)
{
    FcmTestDevice fcmTestDevice;

    fcmTestDevice.attach(getHostname(), getPort(), getRootCerts());
    
    NabtoDevice* dev = fcmTestDevice.device();

    const char* projectId = "foobar";

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    BOOST_REQUIRE(n != NULL);
    BOOST_TEST(nabto_device_fcm_notification_set_project_id(n, projectId) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_fcm_notification_set_payload(n, testFcmPayload.c_str()) == NABTO_DEVICE_EC_OK);

    nabto_device_fcm_notification_free(n);
}

BOOST_AUTO_TEST_CASE(notification_send_not_attached)
{
    FcmTestDevice fcmTestDevice;

    fcmTestDevice.noAttach();
    
    NabtoDevice* dev = fcmTestDevice.device();

    const char* projectId = "foobar";

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    BOOST_REQUIRE(n != NULL);
    BOOST_TEST(nabto_device_fcm_notification_set_project_id(n, projectId) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_fcm_notification_set_payload(n, testFcmPayload.c_str()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* f = nabto_device_future_new(dev);
    nabto_device_fcm_send(n, f);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_NOT_ATTACHED));

    nabto_device_future_free(f);
    nabto_device_fcm_notification_free(n);
}

BOOST_AUTO_TEST_CASE(notification_send_ok)
{
    FcmTestDevice fcmTestDevice;

    fcmTestDevice.attach(getHostname(), getPort(), getRootCerts());
    
    NabtoDevice* dev = fcmTestDevice.device();

    const char* projectId = "foobar";

    NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(dev);
    BOOST_REQUIRE(n != NULL);
    BOOST_TEST(nabto_device_fcm_notification_set_project_id(n, projectId) == NABTO_DEVICE_EC_OK);
    BOOST_TEST(nabto_device_fcm_notification_set_payload(n, testFcmPayload.c_str()) == NABTO_DEVICE_EC_OK);

    NabtoDeviceFuture* f = nabto_device_future_new(dev);
    nabto_device_fcm_send(n, f);
    BOOST_TEST(EC(nabto_device_future_wait(f)) == EC(NABTO_DEVICE_EC_OK));

    nabto_device_future_free(f);
    nabto_device_fcm_notification_free(n);
}


BOOST_AUTO_TEST_SUITE_END()
