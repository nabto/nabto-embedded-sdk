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

    void start(std::function<void (AttachTest& at)> stuff) {
        stuff_ = stuff;
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

    void setDtlsPort(uint16_t port)
    {
        attach_.defaultPort = port;
    }

    static void listener(enum nc_device_event event, void* data)
    {
        AttachTest* at = (AttachTest*)data;
        if (event == NC_DEVICE_EVENT_ATTACHED) {
            at->attachCount_++;
        } else if (event == NC_DEVICE_EVENT_DETACHED) {
            at->detachCount_++;
        }
        at->stuff_(*at);
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
    std::function<void (AttachTest& at)> stuff_;
 public:
    std::atomic<uint64_t> attachCount_ = { 0 };
    std::atomic<uint64_t> detachCount_ = { 0 };
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
    at.start([](nabto::test::AttachTest& at){
            BOOST_TEST(at.attachCount_ == (uint64_t)1);
            at.end();
        });

    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(detach, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);

    // means device detaches after ~200ms
    attachServer->setKeepAliveSettings(100, 50, 2);

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getPort());
    at.start([&attachServer](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1 && at.detachCount_ == 0) {
                attachServer->stop();
            }
            if (at.attachCount_ == 1 &&
                at.detachCount_ == 1)
            {
                at.end();
            }
        });

    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(redirect, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);
    auto redirectServer = nabto::test::RedirectServer::create(ioService->getIoService(), testLogger);
    redirectServer->setRedirect("localhost", attachServer->getPort(), attachServer->getFingerprint());
    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, redirectServer->getPort());
    at.start([](nabto::test::AttachTest& at){
            BOOST_TEST(at.attachCount_ == (uint64_t)1);
            at.end();
        });

    attachServer->stop();
    redirectServer->stop();

    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
    BOOST_TEST(redirectServer->redirectCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(reattach, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);

    // means device detaches after ~200ms
    attachServer->setKeepAliveSettings(100, 50, 2);

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getPort());
    at.start([&ioService, &testLogger, &attachServer](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1 && at.detachCount_ == 0) {
                attachServer->stop();
                attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);
                at.setDtlsPort(attachServer->getPort());
            }
            if (at.attachCount_ == 2 &&
                at.detachCount_ == 1)
            {
                at.end();
            }
        });

    attachServer->stop();
    BOOST_TEST(at.attachCount_ == (uint64_t)2);
}

BOOST_AUTO_TEST_CASE(reattach_after_close_from_server)
{
        auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getPort());
    at.start([&ioService, &testLogger, &attachServer](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1 && at.detachCount_ == 0) {
                attachServer->niceClose();
            }
            if (at.attachCount_ == 2 &&
                at.detachCount_ == 1)
            {
                at.end();
            }
        });

    attachServer->stop();
    BOOST_TEST(at.attachCount_ == (uint64_t)2);
}

BOOST_AUTO_TEST_CASE(retry_after_invalid_coap_response)
{
    // TODO
}

BOOST_AUTO_TEST_CASE(retry_after_server_unavailable)
{
    // TODO
}

BOOST_AUTO_TEST_CASE(reject_invalid_redirect)
{
    // TODO
}

BOOST_AUTO_TEST_CASE(reject_bad_coap_attach_response)
{
    // TODO
}


BOOST_AUTO_TEST_SUITE_END()
