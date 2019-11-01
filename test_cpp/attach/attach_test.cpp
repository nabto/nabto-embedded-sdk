#include <boost/test/unit_test.hpp>

#include <util/io_service.hpp>
#include <util/test_logger.hpp>
#include <dtls/test_certificates.hpp>

#include "attach_server.hpp"
#include <test_platform.hpp>
#include <core/nc_attacher.h>
#include <core/nc_device.h>

namespace nabto {
namespace test {

class AttachTest {
 public:
    AttachTest(nabto::test::TestPlatform& tp, uint16_t port)
        : tp_(tp)
    {
        serverPort_ = port;
    }

    void start() {
        tp_.init();
        BOOST_TEST(nc_udp_dispatch_init(&udpDispatch_, tp_.getPlatform()) == NABTO_EC_OK);
        BOOST_TEST(nc_udp_dispatch_async_bind(&udpDispatch_, tp_.getPlatform(), 0,
                                              &AttachTest::udpDispatchCb, this) == NABTO_EC_OK);

        // blocks until done
        tp_.run();
    }

    void startAttach() {
        nc_coap_client_init(tp_.getPlatform(), &coapClient_);
        nc_attacher_init(&attach_, tp_.getPlatform(), &device_, &coapClient_, &AttachTest::listener, this);
        nc_attacher_set_keys(&attach_,
                             reinterpret_cast<const unsigned char*>(nabto::test::devicePublicKey.c_str()), nabto::test::devicePublicKey.size(),
                             reinterpret_cast<const unsigned char*>(nabto::test::devicePrivateKey.c_str()), nabto::test::devicePrivateKey.size());
        nc_attacher_set_app_info(&attach_, appName_, appVersion_);
        nc_attacher_set_device_info(&attach_, productId_, deviceId_);

        BOOST_TEST(nc_attacher_start(&attach_, hostname_, serverPort_, &udpDispatch_) == NABTO_EC_OK);
    }

    static void listener(enum nc_device_event event, void* data)
    {
        // TODO handle attach events
        BOOST_TEST(event == NC_DEVICE_EVENT_ATTACHED);
        AttachTest* at = (AttachTest*)data;
        at->end();
    }

    static void udpDispatchCb(const np_error_code ec, void* data) {
        BOOST_TEST(ec == NABTO_EC_OK);
        AttachTest* at = (AttachTest*)data;
        at->startAttach();
    }

    void end() {
        nc_attacher_deinit(&attach_);
        nc_coap_client_deinit(&coapClient_);
        nc_udp_dispatch_deinit(&udpDispatch_);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        tp_.stop();
    }
 private:
    nabto::test::TestPlatform& tp_;
    struct nc_attach_context attach_;
    struct nc_device_context device_;
    struct nc_coap_client_context coapClient_;
    struct nc_udp_dispatch_context udpDispatch_;

    uint16_t serverPort_;
    const char* hostname_ = "localhost";
    const char* appName_ = "foo";
    const char* appVersion_ = "bar";
    const char* productId_ = "test";
    const char* deviceId_ = "devTest";
};

} }

BOOST_AUTO_TEST_SUITE(attach)

BOOST_AUTO_TEST_CASE(attach, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getPort());
    at.start();

    attachServer->stop();


}

BOOST_AUTO_TEST_CASE(redirect)
{
    // auto ioService = nabto::IoService::create("test");
    // auto testLogger = nabto::test::TestLogger::create();
    // auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);
    // TODO
}

BOOST_AUTO_TEST_SUITE_END()
