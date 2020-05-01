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
        np_event_queue_create_event(tp_.getPlatform(), &AttachTest::endEvent, this, &endEvent_);
    }

    void start(std::function<void (AttachTest& at)> event, std::function<void (AttachTest& at)> state) {
        event_ = event;
        state_ = state;
        BOOST_TEST(nc_udp_dispatch_init(&udpDispatch_, tp_.getPlatform()) == NABTO_EC_OK);
        nc_udp_dispatch_async_bind(&udpDispatch_, tp_.getPlatform(), 0,
                                   &AttachTest::udpDispatchCb, this);



        // blocks until done
        tp_.run();
    }

    void startAttach() {
        nc_coap_client_init(tp_.getPlatform(), &coapClient_);
        nc_attacher_init(&attach_, tp_.getPlatform(), &device_, &coapClient_, &AttachTest::listener, this);
        nc_attacher_set_state_listener(&attach_, &AttachTest::stateListener, this);
        nc_attacher_set_keys(&attach_,
                             reinterpret_cast<const unsigned char*>(nabto::test::devicePublicKey.c_str()), nabto::test::devicePublicKey.size(),
                             reinterpret_cast<const unsigned char*>(nabto::test::devicePrivateKey.c_str()), nabto::test::devicePrivateKey.size());
        nc_attacher_set_app_info(&attach_, appName_, appVersion_);
        nc_attacher_set_device_info(&attach_, productId_, deviceId_);
        // set timeout to approximately one seconds for the dtls handshake
        nc_attacher_set_handshake_timeout(&attach_, 50, 500);
        attach_.retryWaitTime = 100;
        attach_.accessDeniedWaitTime = 1000;

        BOOST_TEST(nc_attacher_start(&attach_, hostname_, serverPort_, &udpDispatch_) == NABTO_EC_OK);
    }

    void setDtlsPort(uint16_t port)
    {
        attach_.defaultPort = port;
    }

    static void stateListener(enum nc_attacher_attach_state state, void* data)
    {
        AttachTest* at = (AttachTest*)data;
        if (!at->ended_) {
            at->state_(*at);
        }
    }

    static void listener(enum nc_device_event event, void* data)
    {
        AttachTest* at = (AttachTest*)data;
        if (event == NC_DEVICE_EVENT_ATTACHED) {
            at->attachCount_++;
        } else if (event == NC_DEVICE_EVENT_DETACHED) {
            at->detachCount_++;
        }
        if (!at->ended_) {
            at->event_(*at);
        }
    }

    static void udpDispatchCb(const np_error_code ec, void* data) {
        BOOST_TEST(ec == NABTO_EC_OK);
        AttachTest* at = (AttachTest*)data;
        at->startAttach();
    }

    void end() {
        np_event_queue_post(tp_.getPlatform(), endEvent_);
    }

    static void endEvent(void* userData) {
        AttachTest* at = (AttachTest*)userData;
        at->ended_ = true;
        nc_attacher_stop(&at->attach_);
        nc_udp_dispatch_abort(&at->udpDispatch_);
        nc_udp_dispatch_deinit(&at->udpDispatch_);
        at->tp_.stop();
    }
    //    nc_attacher_deinit(&attach_);
    //    nc_coap_client_deinit(&coapClient_);
    //    nc_udp_dispatch_deinit(&udpDispatch_);
        //std::this_thread::sleep_for(std::chrono::milliseconds(200));

    //}

    nabto::test::TestPlatform& tp_;
    struct nc_attach_context attach_;
    struct nc_device_context device_;
    struct nc_coap_client_context coapClient_;
    struct nc_udp_dispatch_context udpDispatch_;

    uint16_t serverPort_;
    const char* hostname_ = "localhost.nabto.net";
    const char* appName_ = "foo";
    const char* appVersion_ = "bar";
    const char* productId_ = "test";
    const char* deviceId_ = "devTest";
    std::function<void (AttachTest& at)> event_;
    std::function<void (AttachTest& at)> state_;
    bool ended_ = false;
    struct np_event* endEvent_;

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
                 if (at.attachCount_ == (uint64_t)1) {
                     at.end();
                 }
             },[](nabto::test::AttachTest& at){ });

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
        },[](nabto::test::AttachTest& at){ });

    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(redirect, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);
    auto redirectServer = nabto::test::RedirectServer::create(ioService->getIoService(), testLogger);
    redirectServer->setRedirect("localhost.nabto.net", attachServer->getPort(), attachServer->getFingerprint());
    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, redirectServer->getPort());
    at.start([](nabto::test::AttachTest& at){
                 if (at.attachCount_ == 1) {
                     at.end();
                 }
        },[](nabto::test::AttachTest& at){ });

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
        },[](nabto::test::AttachTest& at){ });

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
            if (at.attachCount_ == 1 &&
                at.detachCount_ == 1)
            {
                attachServer->stop();
                attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);
                at.setDtlsPort(attachServer->getPort());
            }
            if (at.attachCount_ == 2 &&
                at.detachCount_ == 1)
            {
                at.end();
            }
        },[](nabto::test::AttachTest& at){ });

    attachServer->stop();
    BOOST_TEST(at.attachCount_ == (uint64_t)2);
}

BOOST_AUTO_TEST_CASE(retry_after_server_unavailable)
{
    // the device waits for dtls to timeout and retry again.
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    std::shared_ptr<nabto::test::AttachServer> attachServer;

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, 4242);

    std::thread t([&ioService, &testLogger, &attachServer, &at](){
            std::this_thread::sleep_for(std::chrono::seconds(1));
            attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);
            at.setDtlsPort(attachServer->getPort());
        });
    at.start([](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1)
            {
                at.end();
            }
        },[](nabto::test::AttachTest& at){ });

    t.join();
    attachServer->stop();

    BOOST_TEST(at.attachCount_ == (uint64_t)1);
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(reject_invalid_redirect)
{
    // The redirect is invalid, go to retry
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);
    auto redirectServer = nabto::test::RedirectServer::create(ioService->getIoService(), testLogger);
    redirectServer->setRedirect("localhost.nabto.net", attachServer->getPort(), attachServer->getFingerprint());
    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, redirectServer->getPort());

    redirectServer->invalidRedirect_ = 0;

    at.start([](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1)
            {
                at.end();
            }
        },[](nabto::test::AttachTest& at){ });

    attachServer->stop();
    redirectServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
    BOOST_TEST(redirectServer->redirectCount_ == (uint64_t)2);
}

BOOST_AUTO_TEST_CASE(reject_bad_coap_attach_response)
{
    // The attach did not succeeed, go to retry
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), testLogger);

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getPort());

    attachServer->invalidAttach_ = 0;

    at.start([](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1)
            {
                at.end();
            }
        },[](nabto::test::AttachTest& at){ });

    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)2);
}

BOOST_AUTO_TEST_CASE(access_denied)
{
    // The attach did not succeeed, go to retry
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto accessDeniedServer = nabto::test::AccessDeniedServer::create(ioService->getIoService(), testLogger);

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, accessDeniedServer->getPort());

    at.start([](nabto::test::AttachTest& at){ }, [](nabto::test::AttachTest& at){
                 if (at.attach_.state == NC_ATTACHER_STATE_ACCESS_DENIED_WAIT) {
                     at.end();
                 }
             });

    accessDeniedServer->stop();
}

BOOST_AUTO_TEST_CASE(access_denied_reattach)
{
    // The attach did not succeeed, go to retry
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();
    auto accessDeniedServer = nabto::test::AccessDeniedServer::create(ioService->getIoService(), testLogger);

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, accessDeniedServer->getPort());

    at.start([](nabto::test::AttachTest& at){ }, [&accessDeniedServer](nabto::test::AttachTest& at){
                 if (at.attach_.state == NC_ATTACHER_STATE_ACCESS_DENIED_WAIT &&
                     accessDeniedServer->coapRequestCount_ == 2) {
                     BOOST_TEST(at.attachCount_ == (uint64_t)0);
                     BOOST_TEST(accessDeniedServer->coapRequestCount_ == (uint64_t)2);
                     at.end();
                 }
             });

    accessDeniedServer->stop();
}

BOOST_AUTO_TEST_CASE(redirect_loop_break)
{
    // The attach did not succeeed, go to retry
    auto ioService = nabto::IoService::create("test");
    auto testLogger = nabto::test::TestLogger::create();

    auto redirectServer = nabto::test::RedirectServer::create(ioService->getIoService(), testLogger);
    redirectServer->setRedirect("localhost.nabto.net", redirectServer->getPort(), redirectServer->getFingerprint());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, redirectServer->getPort());

    at.start([](nabto::test::AttachTest& at){ }, [](nabto::test::AttachTest& at){
                if (at.attach_.state == NC_ATTACHER_STATE_RETRY_WAIT) {
                    BOOST_TEST(at.attachCount_ == (uint64_t)0);
                    BOOST_TEST(at.attach_.state == NC_ATTACHER_STATE_RETRY_WAIT);
                    at.end();
                }
             });

    redirectServer->stop();
    BOOST_TEST(redirectServer->redirectCount_ <= (uint64_t)5);
}



BOOST_AUTO_TEST_SUITE_END()
