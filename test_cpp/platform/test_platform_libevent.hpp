#pragma once

#include <platform/np_platform.h>
#include <modules/libevent/nm_libevent.h>
#include <modules/logging/test/nm_logging_test.h>
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/mbedtls/nm_mbedtls_srv.h>
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

        pl_.dns = nm_libevent_dns_get_impl(&libeventContext_);
        pl_.udp = nm_libevent_udp_get_impl(&libeventContext_);
        pl_.tcp = nm_libevent_tcp_get_impl(&libeventContext_);
        pl_.localIp = nm_libevent_local_ip_get_impl(&libeventContext_);
        pl_.timestamp = nm_libevent_timestamp_get_impl(&libeventContext_);

        thread_event_queue_init(&eventQueue_, mutex_, &(pl_.timestamp));
        pl_.eq = thread_event_queue_get_impl(&eventQueue_);

        nm_mbedtls_cli_init(&pl_);
        nm_mbedtls_srv_init(&pl_);
    }

    void deinit()
    {
        thread_event_queue_deinit(&eventQueue_);
        nm_libevent_deinit(&libeventContext_);

    }

    virtual void run()
    {
        event_base_loop(eventBase_, EVLOOP_NO_EXIT_ON_EMPTY);

        // run last events after it has been stopped
        event_base_loop(eventBase_, EVLOOP_NONBLOCK);

        stoppedPromise_.set_value();
    }

    virtual void stop()
    {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        thread_event_queue_stop_blocking(&eventQueue_);
        event_base_loopbreak(eventBase_);

    }

    virtual void waitForStopped()
    {
        std::future<void> fut = stoppedPromise_.get_future();
        fut.get();
    }

    struct np_platform* getPlatform() {
        return &pl_;
    }

 private:
    bool stopped_ = false;
    struct np_platform pl_;
    struct event_base* eventBase_;
    struct nm_libevent_context libeventContext_;
    struct thread_event_queue eventQueue_;
    nabto_device_mutex* mutex_;

    std::promise<void> stoppedPromise_;
};

} } // namespace
