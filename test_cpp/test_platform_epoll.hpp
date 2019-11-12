#pragma once

#include "test_platform.hpp"

#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/epoll/nm_epoll.h>

#include <modules/logging/api/nm_api_logging.h>

namespace nabto {
namespace test {

class TestPlatformEpoll : public TestPlatform {
 public:
    virtual void init()
    {
        np_platform_init(&pl_);
        np_event_queue_init(&pl_, NULL, NULL);
        np_log_init();
        np_communication_buffer_init(&pl_);
        nm_epoll_init(&epoll_, &pl_);
        nm_unix_ts_init(&pl_);
        nm_unix_dns_init(&pl_);
        nm_dtls_cli_init(&pl_);
        nm_dtls_srv_init(&pl_);

        // nm_api_logging_set_level(NABTO_LOG_SEVERITY_LEVEL_TRACE);
        // nm_api_logging_set_callback(&nm_api_logging_std_out_callback, NULL);
    }

    void deinit()
    {
        nm_epoll_close(&epoll_);
    }

    virtual void run()
    {
        int nfds;
        while (true) {
            if (stopped_) {
                deinit();
                return;
            }
            np_event_queue_execute_all(&pl_);
            if (np_event_queue_has_timed_event(&pl_)) {
                uint32_t ms = np_event_queue_next_timed_event_occurance(&pl_);

                nfds = nm_epoll_timed_wait(&epoll_, ms);
            } else {
                nfds = nm_epoll_inf_wait(&epoll_);
            }
            nm_epoll_read(&epoll_, nfds);
        }
    }
    virtual void stop()
    {
        stopped_ = true;
        nm_epoll_break_wait(&epoll_);
    }

    struct np_platform* getPlatform() {
        return &pl_;
    }
 private:
    struct np_platform pl_;
    struct nm_epoll_context epoll_;
    bool stopped_ = false;
};

} } // namespace
