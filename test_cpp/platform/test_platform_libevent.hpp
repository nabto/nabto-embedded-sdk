#pragma once
#include <nabto/nabto_device_config.h>
#include <platform/np_platform.h>
#include <modules/libevent/nm_libevent.h>
#include <modules/libevent/nm_libevent_dns.h>
#include <modules/logging/test/nm_logging_test.h>

#if defined(NABTO_DEVICE_MBEDTLS)
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/mbedtls/nm_mbedtls_spake2.h>
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
#include <modules/mbedtls/nm_mbedtls_srv.h>
#endif
#elif defined(NABTO_DEVICE_WOLFSSL)
#include <modules/wolfssl/nm_wolfssl_cli.h>
#include <modules/wolfssl/nm_wolfssl_spake2.h>
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
#include <modules/wolfssl/nm_wolfssl_srv.h>
#endif
#else
#error Missing DTLS implementation
#endif

#include <modules/communication_buffer/nm_communication_buffer.h>
#include <modules/event_queue/thread_event_queue.h>
#include <api/nabto_device_threads.h>

#include <event2/event.h>
#include <event.h>
#include <event2/thread.h>

#include <future>

namespace nabto {
namespace test {

class TestPlatformLibevent : public TestPlatform {
 public:
    TestPlatformLibevent() {
        memset(&pl_, 0, sizeof(pl_));
        mutex_ = nabto_device_threads_create_mutex();
        nm_libevent_global_init();
        eventBase_ = event_base_new();
        init();
    }

    ~TestPlatformLibevent() {
        stop();
        deinit();


        event_base_free(eventBase_);

        nm_libevent_global_deinit();
        nabto_device_threads_free_mutex(mutex_);
    }

    virtual void init()
    {
        nm_logging_test_init();
        nm_communication_buffer_init(&pl_);
        nm_libevent_init(&libeventContext_, eventBase_);
        nm_libevent_dns_init(&libeventDns_, eventBase_);

        pl_.dns = nm_libevent_dns_get_impl(&libeventDns_);
        pl_.udp = nm_libevent_udp_get_impl(&libeventContext_);
        pl_.tcp = nm_libevent_tcp_get_impl(&libeventContext_);
        pl_.localIp = nm_libevent_local_ip_get_impl(&libeventContext_);
        pl_.timestamp = nm_libevent_timestamp_get_impl(&libeventContext_);

        thread_event_queue_init(&eventQueue_, mutex_, &(pl_.timestamp));
        pl_.eq = thread_event_queue_get_impl(&eventQueue_);

#ifdef NABTO_DEVICE_MBEDTLS
        nm_mbedtls_cli_init(&pl_);
        nm_mbedtls_spake2_init(&pl_);
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
        nm_mbedtls_srv_init(&pl_);
#endif
#endif

#ifdef NABTO_DEVICE_WOLFSSL
        nm_wolfssl_cli_init(&pl_);
        nm_wolfssl_spake2_init(&pl_);
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
        nm_wolfssl_srv_init(&pl_);
#endif
#endif

        thread_event_queue_run(&eventQueue_);

        libeventThread_ =
            std::make_unique<std::thread>([this]() { libeventThread(); });
    }

    void deinit()
    {
        thread_event_queue_deinit(&eventQueue_);
#ifdef NABTO_DEVICE_MBEDTLS
        nm_mbedtls_cli_deinit(&pl_);
#endif
#ifdef NABTO_DEVICE_WOLFSSL
        nm_wolfssl_cli_deinit(&pl_);
#endif
        nm_libevent_dns_deinit(&libeventDns_);
        nm_libevent_deinit(&libeventContext_);

    }

    void libeventThread()
    {
        event_base_loop(eventBase_, EVLOOP_NO_EXIT_ON_EMPTY);

        // run last events after it has been stopped
        event_base_loop(eventBase_, EVLOOP_NONBLOCK);
        prom_.set_value(true);
    }

    virtual void stop()
    {
        if (stopped_) {
            return;
        }
        stopped_ = true;

        nm_libevent_dns_stop(&libeventDns_);

        auto fut = prom_.get_future();
        while (fut.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout) {
            thread_event_queue_stop_blocking(&eventQueue_);
            event_base_loopbreak(eventBase_);
        }

        if (libeventThread_) {
            libeventThread_->join();
        }

    }

    struct np_platform* getPlatform() {
        return &pl_;
    }

 private:
    bool stopped_ = false;
    struct np_platform pl_;
    struct event_base* eventBase_;
    struct nm_libevent_context libeventContext_;
    struct nm_libevent_dns libeventDns_;
    struct thread_event_queue eventQueue_;
    nabto_device_mutex* mutex_;

    std::promise<bool> prom_;
    std::unique_ptr<std::thread> libeventThread_;
};

class TestPlatformLibeventFactory : public TestPlatformFactory {
 public:
    std::shared_ptr<TestPlatform> create()
    {
        return std::make_shared<TestPlatformLibevent>();
    }
};

} } // namespace
