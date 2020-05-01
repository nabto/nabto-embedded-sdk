#pragma once

#include <platform/np_platform.h>
#include <modules/libevent/nm_libevent.h>
#include <modules/logging/test/nm_logging_test.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>

#include "test_platform_event_queue.h"

#include <event2/event.h>
#include <event.h>
#include <event2/thread.h>


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
        //event_free(doOneEvent_);
    }

    virtual void init()
    {
        np_platform_init(&pl_);
        test_platform_event_queue_init(&pl_, eventBase_);
        nm_logging_test_init();
        np_communication_buffer_init(&pl_);
        nm_libevent_init(&pl_, &libeventContext_, eventBase_);
        nm_dtls_cli_init(&pl_);
        nm_dtls_srv_init(&pl_);
    }

    void deinit()
    {
        nm_libevent_deinit(&libeventContext_);
    }

    virtual void run()
    {
        event_base_loop(eventBase_, EVLOOP_NO_EXIT_ON_EMPTY);
    }

    virtual void stop()
    {
        event_base_loopbreak(eventBase_);
    }

    struct np_platform* getPlatform() {
        return &pl_;
    }

 private:
    struct np_platform pl_;
    struct event_base* eventBase_;
    struct nm_libevent_context libeventContext_;
};

} } // namespace
