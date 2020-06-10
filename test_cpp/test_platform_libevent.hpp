#pragma once

#include <platform/np_platform.h>
#include <modules/libevent/nm_libevent.h>
#include <modules/logging/test/nm_logging_test.h>
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/mbedtls/nm_mbedtls_srv.h>
#include <modules/communication_buffer/nm_communication_buffer.h>

#include "test_platform_event_queue.h"

#include <event2/event.h>
#include <event.h>
#include <event2/thread.h>

#include <future>

namespace nabto {
namespace test {

class TestPlatformLibevent : public TestPlatform {
 public:
    TestPlatformLibevent() {
        nm_libevent_global_init();
        eventBase_ = event_base_new();
        init();
    }

    ~TestPlatformLibevent() {
        deinit();
        event_base_free(eventBase_);
        nm_libevent_global_deinit();
    }

    virtual void init()
    {
        eq_ = test_platform_event_queue_init(eventBase_);
        pl_.eq = test_platform_event_queue_get_impl(eq_);
        nm_logging_test_init();
        nm_communication_buffer_init(&pl_);
        nm_libevent_init(&libeventContext_, eventBase_);
        pl_.dns = nm_libevent_dns_get_impl(&libeventContext_);
        pl_.udp = nm_libevent_udp_get_impl(&libeventContext_);
        pl_.tcp = nm_libevent_tcp_get_impl(&libeventContext_);
        pl_.localIp = nm_libevent_local_ip_get_impl(&libeventContext_);
        pl_.timestamp = nm_libevent_timestamp_get_impl(&libeventContext_);

        nm_mbedtls_cli_init(&pl_);
        nm_mbedtls_srv_init(&pl_);
    }

    void deinit()
    {
        nm_libevent_deinit(&libeventContext_);
        test_platform_event_queue_deinit(eq_);
    }

    virtual void run()
    {
        event_base_loop(eventBase_, EVLOOP_NO_EXIT_ON_EMPTY);

        // run last events after it has been stopped
        event_base_loop(eventBase_, EVLOOP_NONBLOCK);

        stopped_.set_value();
    }

    virtual void stop()
    {
        event_base_loopbreak(eventBase_);
    }

    virtual void waitForStopped()
    {
        std::future<void> fut = stopped_.get_future();
        fut.get();
    }

    struct np_platform* getPlatform() {
        return &pl_;
    }

 private:
    struct np_platform pl_;
    struct event_base* eventBase_;
    struct nm_libevent_context libeventContext_;
    struct test_platform_event_queue* eq_;

    std::promise<void> stopped_;
};

} } // namespace
