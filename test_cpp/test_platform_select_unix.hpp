#pragma once

#include "test_platform.hpp"
#include "test_platform_event_queue.h"

#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/mbedtls/nm_dtls_cli.h>
#include <modules/mbedtls/nm_dtls_srv.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/select_unix/nm_select_unix.h>
#include <modules/logging/test/nm_logging_test.h>
#include <modules/libevent/nm_libevent.h>

#include <thread>
#include <future>

#include <event.h>

namespace nabto {
namespace test {


class TestPlatformSelectUnix : public TestPlatform {
 public:

    TestPlatformSelectUnix() {
        nm_libevent_global_init();
        eventBase_ = event_base_new();
        init();
    }

    ~TestPlatformSelectUnix() {
        deinit();
        event_base_free(eventBase_);
        nm_libevent_global_deinit();
    }

    virtual void init()
    {
        test_platform_event_queue_init(&pl_, eventBase_);
        nm_logging_test_init();
        np_communication_buffer_init(&pl_);
        nm_select_unix_init(&selectCtx_, &pl_);
        nm_unix_ts_init(&pl_);
        nm_unix_dns_init(&pl_);
        nm_dtls_cli_init(&pl_);
        nm_dtls_srv_init(&pl_);
    }

    void deinit()
    {
        nm_select_unix_close(&selectCtx_);
        if (networkThread_) {
            networkThread_->join();
        }
        test_platform_event_queue_deinit(&pl_);
    }

    virtual void run()
    {
        networkThread_ = std::make_unique<std::thread>(&TestPlatformSelectUnix::networkThread, this);
        event_base_loop(eventBase_, EVLOOP_NO_EXIT_ON_EMPTY);
        // run last events after it has been stopped
        event_base_loop(eventBase_, EVLOOP_NONBLOCK);

        stoppedPromise_.set_value();
    }

    static void networkThread(TestPlatformSelectUnix* tp)
    {
        int nfds;
        while (true) {
            if (tp->stopped_) {
                return;
            }
            nfds = nm_select_unix_inf_wait(&tp->selectCtx_);
            nm_select_unix_read(&tp->selectCtx_, nfds);
        }
    }

    virtual void stop()
    {
        stopped_ = true;
        nm_select_unix_notify(&selectCtx_);
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
    struct np_platform pl_;
    struct nm_select_unix selectCtx_;
    bool stopped_ = false;
    std::unique_ptr<std::thread> networkThread_;
    struct event_base* eventBase_;
    std::promise<void> stoppedPromise_;
};


} } // namespace
