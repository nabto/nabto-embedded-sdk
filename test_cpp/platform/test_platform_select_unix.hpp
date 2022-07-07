#pragma once

#include "test_platform.hpp"

#include <platform/np_platform.h>
#include <platform/np_logging.h>

#if defined(NABTO_USE_MBEDTLS)
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/mbedtls/nm_mbedtls_srv.h>
#include <modules/mbedtls/nm_mbedtls_spake2.h>
#elif defined(NABTO_USE_WOLFSSL)
#include <modules/wolfssl/nm_wolfssl_cli.h>
#include <modules/wolfssl/nm_wolfssl_srv.h>
#include <modules/wolfssl/nm_wolfssl_spake2.h>
#else
#error Missing DTLS implementation
#endif

#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/select_unix/nm_select_unix.h>
#include <modules/logging/test/nm_logging_test.h>
#include <modules/event_queue/thread_event_queue.h>
#include <modules/communication_buffer/nm_communication_buffer.h>

#include <thread>
#include <future>

#include <event.h>

namespace nabto {
namespace test {


class TestPlatformSelectUnix : public TestPlatform {
 public:

    TestPlatformSelectUnix() {
        memset(&pl_, 0, sizeof(pl_));
        mutex_ = nabto_device_threads_create_mutex();
        init();
    }

    ~TestPlatformSelectUnix() {
        stop();
        deinit();
        nabto_device_threads_free_mutex(mutex_);
    }

    virtual void init()
    {
        nm_logging_test_init();
        nm_communication_buffer_init(&pl_);
        nm_select_unix_init(&selectCtx_);

        nm_unix_dns_resolver_init(&dns_);

        pl_.timestamp = nm_unix_ts_get_impl();

        thread_event_queue_init(&eventQueue_, mutex_, &pl_.timestamp);

        pl_.tcp = nm_select_unix_tcp_get_impl(&selectCtx_);
        pl_.udp = nm_select_unix_udp_get_impl(&selectCtx_);
        pl_.dns = nm_unix_dns_resolver_get_impl(&dns_);
        pl_.eq = thread_event_queue_get_impl(&eventQueue_);

#if defined(NABTO_USE_MBEDTLS)
        nm_mbedtls_cli_init(&pl_);
        nm_mbedtls_srv_init(&pl_);
        nm_mbedtls_spake2_init(&pl_);
#elif defined(NABTO_USE_WOLFSSL)
        nm_wolfssl_cli_init(&pl_);
        nm_wolfssl_srv_init(&pl_);
        nm_wolfssl_spake2_init(&pl_);
#else
#error Missing DTLS implementation
#endif

        nm_unix_dns_resolver_run(&dns_);
        thread_event_queue_run(&eventQueue_);

        nm_select_unix_run(&selectCtx_);
    }

    void deinit()
    {
        nm_unix_dns_resolver_deinit(&dns_);
        nm_select_unix_deinit(&selectCtx_);
        thread_event_queue_deinit(&eventQueue_);
    }

    virtual void stop()
    {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        nm_select_unix_stop(&selectCtx_);
        nm_select_unix_notify(&selectCtx_);
        thread_event_queue_stop_blocking(&eventQueue_);
    }

    struct np_platform* getPlatform() {
        return &pl_;
    }
 private:
    struct np_platform pl_;
    struct nm_select_unix selectCtx_;
    bool stopped_ = false;
    struct nm_unix_dns_resolver dns_;
    struct thread_event_queue eventQueue_;
    struct nabto_device_mutex* mutex_;
};

class TestPlatformSelectUnixFactory : public TestPlatformFactory {
 public:
    std::shared_ptr<TestPlatform> create() {
        return std::make_shared<TestPlatformSelectUnix>();
    }
};

} } // namespace
