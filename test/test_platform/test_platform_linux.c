#include "test_platform.h"

#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/epoll/nm_epoll.h>
#include <modules/mdns/nm_mdns.h>
#include <modules/logging/test/nm_logging_test.h
#include <modules/communication_buffer/nm_communication_buffer.h>

struct nm_epoll_context epoll;

void test_platform_init(struct test_platform* tp)
{
    struct np_platform* pl = &tp->pl;
    np_event_queue_init(pl, NULL, NULL);
    nm_logging_test_init();
    nm_communication_buffer_init(pl);
    nm_epoll_init(&epoll, pl);
    nm_unix_ts_init(pl);
    nm_unix_dns_init(pl);
    nm_mbedtls_cli_init(pl);
    nm_mdns_init(pl);

    tp->stopped = false;
}


void test_platform_run(struct test_platform* tp)
{
    int nfds;
    while (true) {
        if (tp->stopped) {
            return;
        }
        np_event_queue_execute_all(&tp->pl);
        if (np_event_queue_has_timed_event(&tp->pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&tp->pl);

            nfds = nm_epoll_timed_wait(&epoll, ms);
        } else {
            nfds = nm_epoll_inf_wait(&epoll);
        }
        nm_epoll_read(&epoll, nfds);
    }
}

void test_platform_stop(struct test_platform* tp)
{
    tp->stopped = true;
    nm_epoll_break_wait(&epoll);
}
