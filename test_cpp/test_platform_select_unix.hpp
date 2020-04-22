#pragma once

#include "test_platform.hpp"

#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/select_unix/nm_select_unix.h>
#include <modules/logging/test/nm_logging_test.h>


namespace nabto {
namespace test {


class TestPlatformSelectUnix : public TestPlatform {
 public:

    TestPlatformSelectUnix() {
        init();
    }

    ~TestPlatformSelectUnix() {
        //deinit();
    }

    virtual void init()
    {
        np_platform_init(&pl_);
        np_event_queue_init(&pl_, NULL, NULL);
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
    }

    virtual void run()
    {
        int nfds;
        while (true) {
            if (stopped_ && nm_select_unix_finished(&selectCtx_)) {
                deinit();
                return;
            }
            np_event_queue_execute_all(&pl_);
            if (np_event_queue_has_timed_event(&pl_)) {
                uint32_t ms = np_event_queue_next_timed_event_occurance(&pl_);

                nfds = nm_select_unix_timed_wait(&selectCtx_, ms);
            } else {
                nfds = nm_select_unix_inf_wait(&selectCtx_);
            }
            nm_select_unix_read(&selectCtx_, nfds);
        }
    }
    virtual void stop()
    {
        stopped_ = true;
        nm_select_unix_break_wait(&selectCtx_);
    }

    struct np_platform* getPlatform() {
        return &pl_;
    }
 private:
    struct np_platform pl_;
    struct nm_select_unix selectCtx_;
    bool stopped_ = false;
};


} } // namespace
