#pragma once

#include <modules/libevent/nm_libevent.h>

#include <event2/event.h>



namespace nabto {
namespace test {

class TestPlatformLibevent : public TestPlatform {
 public:
    TestPlatformLibevent() {
        eventBase_ = event_base_new();
    }

    ~TestPlatformLibevent() {
        event_base_free(eventBase_);
    }

    virtual void init()
    {
        np_platform_init(&pl_);
        np_event_queue_init(&pl_, NULL, NULL);
        nm_logging_test_init();
        np_communication_buffer_init(&pl_);
        nm_libevent_init(&pl_, eventBase_);
        nm_unix_ts_init(&pl_);
        nm_dtls_cli_init(&pl_);
        nm_dtls_srv_init(&pl_);
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

};

} } // namespace
