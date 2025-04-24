#include <boost/test/unit_test.hpp>

#include <platform/np_event_queue_wrapper.h>

#include <core/nc_attacher.h>
#include <core/nc_device.h>
#include <core/nc_stun.h>

#include <util/io_service.hpp>
#include <fixtures/dtls_server/test_certificates.hpp>

#include "attach_server.hpp"
#include <test_platform.hpp>

#include <future>

#include "certificates.hpp"

namespace nabto {
namespace test {

class AttachTest {
 public:
    AttachTest(nabto::test::TestPlatform& tp, const std::string& hostname, uint16_t port, const std::string& rcs)
        : tp_(tp), hostname_(hostname), serverPort_(port), rootCerts_(rcs)
    {
        struct np_platform* pl = tp_.getPlatform();
        np_completion_event_init(&pl->eq, &boundCompletionEvent, &AttachTest::udpDispatchCb, this);
        memset(&device_, 0, sizeof(device_));
    }

    ~AttachTest()
    {
        nc_coap_client_stop(&coapClient_);
        tp_.stop();
        nc_attacher_deinit(&attach_);
        nc_coap_client_deinit(&coapClient_);
        nc_stun_deinit(&device_.stun);
        nc_udp_dispatch_deinit(&udpDispatch_);
        np_completion_event_deinit(&boundCompletionEvent);
    }

    void addSct(std::string sct) {
        sct_ = sct;
    }

    static void udpEvent(enum nc_device_event event, void* data)
    {
        // we do not test udp socket failures here, just ignore event
    }

    void start(std::function<void (AttachTest& at)> event, std::function<void (AttachTest& at)> state) {
        event_ = event;
        state_ = state;
        BOOST_TEST(nc_udp_dispatch_init(&udpDispatch_, tp_.getPlatform(), &AttachTest::udpEvent, this) == NABTO_EC_OK);
        nc_udp_dispatch_async_bind(&udpDispatch_, tp_.getPlatform(), 0,
                                   &boundCompletionEvent);
    }

    void startAttach() {
        nc_stun_init(&device_.stun, &device_, tp_.getPlatform());
        nc_coap_client_init(tp_.getPlatform(), &coapClient_);
        nc_attacher_init(&attach_, tp_.getPlatform(), &device_, &coapClient_, &AttachTest::listener, this);
        nc_attacher_set_state_listener(&attach_, &AttachTest::stateListener, this);
        nc_attacher_set_keys(&attach_,
                             reinterpret_cast<const unsigned char*>(nabto::test::devicePublicKey.c_str()), nabto::test::devicePublicKey.size(),
                             reinterpret_cast<const unsigned char*>(nabto::test::devicePrivateKey.c_str()), nabto::test::devicePrivateKey.size());
        nc_attacher_set_root_certs(&attach_, rootCerts_.c_str());
        nc_attacher_set_app_info(&attach_, appName_, appVersion_);
        nc_attacher_set_device_info(&attach_, productId_.c_str(), deviceId_.c_str());
        // set timeout to approximately one seconds for the dtls handshake
        nc_attacher_set_handshake_timeout(&attach_, 50, 500);
        attach_.retryWaitTime = 100;
        attach_.accessDeniedWaitTime = 1000;

        if (!sct_.empty()) {
            nc_attacher_add_server_connect_token(&attach_, sct_.c_str());
        }

        BOOST_TEST(nc_attacher_start(&attach_, hostname_.c_str(), serverPort_, &udpDispatch_) == NABTO_EC_OK);
        state_(*this);
    }

    void setDtlsPort(uint16_t port)
    {
        attach_.defaultPort = port;
    }

    void niceClose(std::function<void (AttachTest& at)> cb)
    {
        closed_ = cb;
        nc_attacher_async_close(&attach_, &AttachTest::closeCb, this);
    }

    static void closeCb(void* data)
    {
        AttachTest* at = (AttachTest*)data;
        if (!at->ended_)  {
            at->closed_(*at);
        }
    }

    static void stateListener(enum nc_attacher_attach_state state, void* data)
    {
        (void)state;
        AttachTest* at = (AttachTest*)data;
        if (!at->ended_) {
            at->state_(*at);
        }
    }

    static void listener(enum nc_device_event event, void* data)
    {
        AttachTest* at = (AttachTest*)data;
        at->lastDevEvent_ = event;
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
        nc_udp_dispatch_start_recv(&at->udpDispatch_);
        at->startAttach();
    }

    void end() {
        ended_ = true;
        nc_attacher_stop(&attach_);
        nc_udp_dispatch_abort(&udpDispatch_);
        testEnded_.set_value();
    }

    void waitForTestEnd() {
        std::future<void> fut = testEnded_.get_future();
        fut.get();
    }

    static void turnCb(const np_error_code ec, void* userData)
    {
        BOOST_TEST(ec == NABTO_EC_OK);
        AttachTest* at = (AttachTest*)userData;
        at->turnCb_(*at, ec, &at->turn_);
        nc_attacher_ice_servers_ctx_deinit(&at->turn_);
    }

    void getTurnServers(std::string identifier, std::function<void(nabto::test::AttachTest& at, const np_error_code ec, struct nc_attacher_request_ice_servers_context* ctx)> cb)
    {
        nc_attacher_ice_servers_ctx_init(&turn_, &attach_);
        turnCb_ = cb;
        nc_attacher_request_ice_servers(&turn_, identifier.c_str(), &AttachTest::turnCb, this);

    }

    nabto::test::TestPlatform& tp_;
    struct nc_attach_context attach_;
    struct nc_device_context device_;
    struct nc_coap_client_context coapClient_;
    struct nc_udp_dispatch_context udpDispatch_;
    struct nc_attacher_request_ice_servers_context turn_;

    struct np_completion_event boundCompletionEvent;

    std::string hostname_;
    uint16_t serverPort_;
    std::string rootCerts_;
    const char* appName_ = "foo";
    const char* appVersion_ = "bar";
    std::string productId_ = "test";
    std::string deviceId_ = "devTest";
    std::string sct_ = "";
    const unsigned char* devPupKey_ = reinterpret_cast<const unsigned char*>(nabto::test::devicePublicKey.c_str());
    size_t devPubKeySize_ = nabto::test::devicePublicKey.size();
    const unsigned char* devPrivKey_ = reinterpret_cast<const unsigned char*>(nabto::test::devicePrivateKey.c_str());
    size_t devPrivKeySize_ = nabto::test::devicePrivateKey.size();

    std::function<void (AttachTest& at)> event_;
    std::function<void (AttachTest& at)> state_;
    std::function<void (AttachTest& at)> closed_;
    std::function<void(nabto::test::AttachTest& at, const np_error_code ec, struct nc_attacher_request_ice_servers_context* ctx)> turnCb_;

    bool ended_ = false;
    struct np_event* endEvent_;
    enum nc_device_event lastDevEvent_ = NC_DEVICE_EVENT_DETACHED;

    std::atomic<uint64_t> attachCount_ = { 0 };
    std::atomic<uint64_t> detachCount_ = { 0 };
    std::promise<void> testEnded_;

};

} }

BOOST_AUTO_TEST_SUITE(attach)

BOOST_AUTO_TEST_CASE(attach_close, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){
                 if (at.attachCount_ == (uint64_t)1) {
                     at.niceClose([](nabto::test::AttachTest& at) {
                                      at.end();
                                  });
                 }
             },[](nabto::test::AttachTest& at){(void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}


BOOST_AUTO_TEST_CASE(attach_sct, *boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.addSct("foobar");
    at.start([](nabto::test::AttachTest& at) {
        if (at.attachCount_ == (uint64_t)1) {
            at.niceClose([](nabto::test::AttachTest& at) {
                at.end();
                });
        }
        }, [](nabto::test::AttachTest& at) {(void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(attach_close_start, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){
                 if (at.attachCount_ == (uint64_t)1) {
                     at.niceClose([](nabto::test::AttachTest& at) {
                                      BOOST_TEST(nc_attacher_start(&at.attach_, at.hostname_.c_str(), at.serverPort_, &at.udpDispatch_) == NABTO_EC_INVALID_STATE);
                                      at.end();
                                  });
                 }
             },[](nabto::test::AttachTest& at){(void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(attach_close_restart, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){
                 if (at.attachCount_ == (uint64_t)1) {
                     at.niceClose([](nabto::test::AttachTest& at) {
                                      BOOST_TEST(nc_attacher_restart(&at.attach_) == NABTO_EC_OK);
                                  });
                 } else {
                     at.niceClose([](nabto::test::AttachTest& at) {
                                      at.end();
                                  });
                 }
             },[](nabto::test::AttachTest& at){(void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)2);
}

BOOST_AUTO_TEST_CASE(restart_from_dns_state, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());

    at.start([](nabto::test::AttachTest& at){
                 if (at.attachCount_ == (uint64_t)1) {
                     at.niceClose([](nabto::test::AttachTest& at) {
                                      at.end();
                                  });
                 }

             },
        [=](nabto::test::AttachTest& at){
            if (at.attach_.state == NC_ATTACHER_STATE_DNS) {
                nc_attacher_stop(&at.attach_);
                BOOST_TEST(nc_attacher_restart(&at.attach_) == NABTO_EC_OK);
            }
        });
    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(restart_from_dtls_req, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    bool first = true;
    at.start([](nabto::test::AttachTest& at){
                 if (at.attachCount_ == (uint64_t)1) {
                     at.niceClose([](nabto::test::AttachTest& at) {
                                      at.end();
                                  });
                 }

             },
        [=, &first](nabto::test::AttachTest& at){
            if (first && at.attach_.state == NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST) {
                first = false;
                nc_attacher_stop(&at.attach_);
                BOOST_TEST(nc_attacher_restart(&at.attach_) == NABTO_EC_OK);
            }
        });
    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(wrong_root_cert, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    // nabtoRootCA1 cannot validate the test certificate the test attach server is using.
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), nabto::test::nabtoRootCA1);
    at.start([](nabto::test::AttachTest& at){(void)at;},
             [](nabto::test::AttachTest& at){
                     if (at.attach_.state == NC_ATTACHER_STATE_RETRY_WAIT) {
                         at.end();
                     }
                 });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)0);
}

BOOST_AUTO_TEST_CASE(wrong_hostname, * boost::unit_test::timeout(300))
{
    // test that we cannot attach if the hostname does not match the certificate
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, "localhost.nabto.net", attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){(void)at;},[](nabto::test::AttachTest& at){
                     if (at.attach_.state == NC_ATTACHER_STATE_RETRY_WAIT) {
                         at.end();
                     }
                 });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)0);
}

BOOST_AUTO_TEST_CASE(wrong_alp, * boost::unit_test::timeout(300))
{
    // test that we cannot attach if the hostname does not match the certificate
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create_alpn(ioService->getIoService(), {"foobar"});

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){(void)at;},[](nabto::test::AttachTest& at){
                     if (at.attach_.state == NC_ATTACHER_STATE_RETRY_WAIT) {
                         at.end();
                     }
                 });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)0);
}

BOOST_AUTO_TEST_CASE(attach_close_before_attach, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){(void)at; },[](nabto::test::AttachTest& at){
                 if (at.attach_.state == NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST) {
                     at.niceClose([](nabto::test::AttachTest& at) {
                                      at.end();
                                  });
                 }
             });

    at.waitForTestEnd();
    attachServer->stop();
}

BOOST_AUTO_TEST_CASE(attach, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){
                 if (at.attachCount_ == (uint64_t)1) {
                     at.end();
                 }
             },[](nabto::test::AttachTest& at){(void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

/**
 * This test sets the server timeout greater than the client timeout, and sets
 * the server to drop the 3rd packet it receives. This is here as wolfssl seems
 * to have an issue here.
 */
BOOST_AUTO_TEST_CASE(attach_packet_loss, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), 2000, 16000);
    attachServer->dropNthPacket(3);

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){
                 if (at.attachCount_ == (uint64_t)1) {
                     at.end();
                 }
             },[](nabto::test::AttachTest& at){(void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(detach, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    // means device detaches after ~200ms
    attachServer->setKeepAliveSettings(100, 50, 2);

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([&attachServer](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1 && at.detachCount_ == 0) {
                attachServer->stop();
            }
            if (at.attachCount_ == 1 &&
                at.detachCount_ == 1)
            {
                at.end();
            }
        },[](nabto::test::AttachTest& at){(void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(redirect, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());
    auto redirectServer = nabto::test::RedirectServer::create(ioService->getIoService());
    redirectServer->setRedirect("localhost-multi.nabto.net", attachServer->getPort(), attachServer->getFingerprint());
    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, redirectServer->getHostname(), redirectServer->getPort(), redirectServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){
                 if (at.attachCount_ == 1) {
                     at.end();
                 }
        },[](nabto::test::AttachTest& at){(void)at; });
    at.waitForTestEnd();
    attachServer->stop();
    redirectServer->stop();

    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
    BOOST_TEST(redirectServer->redirectCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(reattach, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    // means device detaches after ~200ms
    attachServer->setKeepAliveSettings(100, 50, 2);

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([&ioService, &attachServer](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1 && at.detachCount_ == 0) {
                attachServer->stop();
                attachServer = nabto::test::AttachServer::create(ioService->getIoService());
                at.setDtlsPort(attachServer->getPort());
            }
            if (at.attachCount_ == 2 &&
                at.detachCount_ == 1)
            {
                at.end();
            }
        },[](nabto::test::AttachTest& at){(void)at; });
    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(at.attachCount_ == (uint64_t)2);
}

BOOST_AUTO_TEST_CASE(reattach_after_close_from_server, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([&attachServer](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1 && at.detachCount_ == 0) {
                attachServer->niceClose();
            }
            if (at.attachCount_ == 1 &&
                at.detachCount_ == 1)
            {

            }
            if (at.attachCount_ == 2 &&
                at.detachCount_ == 1)
            {
                at.end();
            }
        },[](nabto::test::AttachTest& at){(void)at; });
    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(at.attachCount_ == (uint64_t)2);
}

BOOST_AUTO_TEST_CASE(retry_after_server_unavailable, * boost::unit_test::timeout(300))
{
    // the device waits for dtls to timeout and retry again.
    auto ioService = nabto::IoService::create("test");
    std::shared_ptr<nabto::test::AttachServer> attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), 4242, attachServer->getRootCerts());

    std::thread t([&attachServer, &at](){
            std::this_thread::sleep_for(std::chrono::seconds(1));
            at.setDtlsPort(attachServer->getPort());
        });
    at.start([](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1)
            {
                at.end();
            }
        },[](nabto::test::AttachTest& at){(void)at; });

    t.join();
    at.waitForTestEnd();
    attachServer->stop();

    BOOST_TEST(at.attachCount_ == (uint64_t)1);
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(reject_invalid_redirect, * boost::unit_test::timeout(300))
{
    // The redirect is invalid, go to retry
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());
    auto redirectServer = nabto::test::RedirectServer::create(ioService->getIoService());
    redirectServer->setRedirect("localhost-multi.nabto.net", attachServer->getPort(), attachServer->getFingerprint());
    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, redirectServer->getHostname(), redirectServer->getPort(), redirectServer->getRootCerts());

    redirectServer->invalidRedirect_ = 0;

    at.start([](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1)
            {
                at.end();
            }
        },[](nabto::test::AttachTest& at){(void)at; });
    at.waitForTestEnd();
    attachServer->stop();
    redirectServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
    BOOST_TEST(redirectServer->redirectCount_ == (uint64_t)2);
}

BOOST_AUTO_TEST_CASE(reject_bad_coap_attach_response, * boost::unit_test::timeout(300))
{
    // The attach did not succeeed, go to retry
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());

    attachServer->invalidAttach_ = 0;

    at.start([](nabto::test::AttachTest& at){
            if (at.attachCount_ == 1)
            {
                at.end();
            }
        },[](nabto::test::AttachTest& at){(void)at; });
    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)2);
}

BOOST_AUTO_TEST_CASE(access_denied, * boost::unit_test::timeout(300))
{
    // The attach did not succeeed, go to retry
    auto ioService = nabto::IoService::create("test");
    auto accessDeniedServer = nabto::test::AccessDeniedServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, accessDeniedServer->getHostname(), accessDeniedServer->getPort(), accessDeniedServer->getRootCerts());

    at.start([](nabto::test::AttachTest& at){(void)at; }, [](nabto::test::AttachTest& at){
                 if (at.attach_.state == NC_ATTACHER_STATE_ACCESS_DENIED_WAIT) {
                     at.end();
                 }
             });
    at.waitForTestEnd();
    accessDeniedServer->stop();
}

BOOST_AUTO_TEST_CASE(access_denied_reattach, * boost::unit_test::timeout(300))
{
    // The attach did not succeeed, go to retry
    auto ioService = nabto::IoService::create("test");
    auto accessDeniedServer = nabto::test::AccessDeniedServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, accessDeniedServer->getHostname(), accessDeniedServer->getPort(), accessDeniedServer->getRootCerts());

    at.start([](nabto::test::AttachTest& at){(void)at; }, [&accessDeniedServer](nabto::test::AttachTest& at){
                 if (at.attach_.state == NC_ATTACHER_STATE_ACCESS_DENIED_WAIT &&
                     accessDeniedServer->coapRequestCount_ >= 2) {
                     BOOST_TEST(at.attachCount_ == (uint64_t)0);
                     at.end();
                 }
             });
    at.waitForTestEnd();
    accessDeniedServer->stop();
}

BOOST_AUTO_TEST_CASE(redirect_loop_break, * boost::unit_test::timeout(300))
{
    // The attach did not succeeed, go to retry
    auto ioService = nabto::IoService::create("test");

    auto redirectServer = nabto::test::RedirectServer::create(ioService->getIoService());
    redirectServer->setRedirect("localhost-multi.nabto.net", redirectServer->getPort(), redirectServer->getFingerprint());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, redirectServer->getHostname(), redirectServer->getPort(), redirectServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){(void)at; }, [](nabto::test::AttachTest& at){
                if (at.attach_.state == NC_ATTACHER_STATE_RETRY_WAIT) {
                    BOOST_TEST(at.attachCount_ == (uint64_t)0);
                    BOOST_TEST(at.attach_.state == NC_ATTACHER_STATE_RETRY_WAIT);
                    at.end();
                }
             });
    at.waitForTestEnd();
    redirectServer->stop();
    BOOST_TEST(redirectServer->redirectCount_ <= (uint64_t)5);
}

#ifdef __linux__
BOOST_AUTO_TEST_CASE(attach_ha, * boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), "127.0.0.2", 0);
    auto attachServer2 = nabto::test::AttachServer::create(ioService->getIoService(), "127.0.0.1", attachServer->getPort());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){
                 if (at.attachCount_ == (uint64_t)1) {
                     at.end();
                 }
             },[](nabto::test::AttachTest& at){
                   BOOST_TEST(at.attach_.state != NC_ATTACHER_STATE_RETRY_WAIT);
               });

    at.waitForTestEnd();
    attachServer->stop();
    attachServer2->stop();
    BOOST_TEST(attachServer->attachCount_+attachServer2->attachCount_ == (uint64_t)1);
}
#endif

BOOST_AUTO_TEST_CASE(attach_wrong_fp, * boost::unit_test::timeout(300))
{
    std::array<uint8_t,32> fp;
    fp.fill(42);
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());
    attachServer->deviceFp_ = fp.data();

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){
                 BOOST_TEST(at.lastDevEvent_ == NC_DEVICE_EVENT_UNKNOWN_FINGERPRINT);
                 at.niceClose([](nabto::test::AttachTest& at) {
                                  at.end();
                              });
             },[](nabto::test::AttachTest& at){(void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)0);
}

BOOST_AUTO_TEST_CASE(attach_wrong_device_id, * boost::unit_test::timeout(300))
{
    const char* dId = "not_correct_device_id";
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());
    attachServer->deviceId_ = dId;

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){
                 BOOST_TEST(at.lastDevEvent_ == NC_DEVICE_EVENT_WRONG_DEVICE_ID);
                 at.niceClose([](nabto::test::AttachTest& at) {
                                  at.end();
                              });
             },[](nabto::test::AttachTest& at){(void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)0);
}

BOOST_AUTO_TEST_CASE(attach_wrong_product_id, * boost::unit_test::timeout(300))
{
    const char* pId = "not_correct_product_id";
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());
    attachServer->productId_ = pId;

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    at.start([](nabto::test::AttachTest& at){
                 BOOST_TEST(at.lastDevEvent_ == NC_DEVICE_EVENT_WRONG_PRODUCT_ID);
                 at.niceClose([](nabto::test::AttachTest& at) {
                                  at.end();
                              });
             },[](nabto::test::AttachTest& at){(void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)0);
}

BOOST_AUTO_TEST_CASE(attach_correct_info, * boost::unit_test::timeout(300))
{
    // Test to validate that fp, deviceId, ProductId can be set in the attachServer and attach
    // succeeds. This tests the test code to have more confidence in the 3 previous tests.
    std::array<uint8_t, 32> fp = {221, 95, 236, 79, 39, 181, 101, 124, 183, 94, 94, 36, 127, 231, 146, 204, 9, 106, 220, 54, 112, 137, 118, 96, 148, 98, 120, 214, 125, 157, 149, 247};
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    attachServer->productId_ = at.productId_.c_str();
    attachServer->deviceId_ = at.deviceId_.c_str();
    attachServer->deviceFp_ = fp.data();

    at.start(
        [](nabto::test::AttachTest& at) {
            if (at.lastDevEvent_ == NC_DEVICE_EVENT_ATTACHED) {
                at.niceClose([](nabto::test::AttachTest& at) { at.end(); });
            }
        },
        [](nabto::test::AttachTest& at) { (void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_CASE(attach_expired_certificate, *boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService(), {nabto::test::expiredLocalhostMultiNabtoNetCert, nabto::test::testIntermediateCert });

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(),
                               attachServer->getPort(),
                               attachServer->getRootCerts());
    at.start(
        [](nabto::test::AttachTest& at) {
            BOOST_TEST(at.lastDevEvent_ ==
                       NC_DEVICE_EVENT_CERTIFICATE_VALIDATION_FAILED);
            at.niceClose([](nabto::test::AttachTest& at) { at.end(); });
        },
        [](nabto::test::AttachTest& at) { (void)at; });

    at.waitForTestEnd();
    attachServer->stop();
}

BOOST_AUTO_TEST_CASE(get_turn, *boost::unit_test::timeout(300))
{
    auto ioService = nabto::IoService::create("test");
    auto attachServer = nabto::test::AttachServer::create(ioService->getIoService());

    auto tp = nabto::test::TestPlatform::create();
    nabto::test::AttachTest at(*tp, attachServer->getHostname(), attachServer->getPort(), attachServer->getRootCerts());
    std::string identifier = "foobar";

    at.start([identifier](nabto::test::AttachTest& at) {
        at.getTurnServers(identifier, [identifier](nabto::test::AttachTest& at, const np_error_code ec, struct nc_attacher_request_ice_servers_context* ctx){
            void* elm;
            NN_VECTOR_FOREACH_REFERENCE(elm, &ctx->iceServers) {
                struct nc_attacher_ice_server* ts = (struct nc_attacher_ice_server*)elm;
                if (ts->username != NULL){
                    std::string un(ts->username);
                    BOOST_TEST(un == at.productId_ + ":" + at.deviceId_ + ":" + identifier);
                }
                bool is1 = false;
                bool is2 = false;

                if (ts->credential != NULL) {
                    std::string cred(ts->credential);
                    BOOST_TEST(((is1 = cred == "verySecretAccessKey") || (is2 = cred == "anotherVerySecretAccessKey") || (ts->credential == NULL)));
                }
                if (is1) {
                    char* url = NULL;
                    BOOST_TEST(nn_vector_size(&ts->urls) == (size_t)2);
                    nn_vector_get(&ts->urls, 0, &url);
                    BOOST_TEST((url != NULL));
                    BOOST_TEST(std::string(url) == "turn:turn.nabto.net:9991?transport=udp");

                    url = NULL;
                    nn_vector_get(&ts->urls, 1, &url);
                    BOOST_TEST((url != NULL));
                    BOOST_TEST(std::string(url) == "turn:turn.nabto.net:9991?transport=tcp");
                } else if (is2) {
                    char* url;
                    BOOST_TEST(nn_vector_size(&ts->urls) == (size_t)1);
                    nn_vector_get(&ts->urls, 0, &url);
                    BOOST_TEST(std::string(url) == "turns:turn.nabto.net:443?transport=tcp");

                } else {
                    char* url;
                    BOOST_TEST(nn_vector_size(&ts->urls) == (size_t)1);
                    nn_vector_get(&ts->urls, 0, &url);
                    BOOST_TEST(std::string(url) == "stun:stun.nabto.net:5874");

                }
            }
            at.end();
        });
        }, [](nabto::test::AttachTest& at) {(void)at; });

    at.waitForTestEnd();
    attachServer->stop();
    BOOST_TEST(attachServer->attachCount_ == (uint64_t)1);
}

BOOST_AUTO_TEST_SUITE_END()
