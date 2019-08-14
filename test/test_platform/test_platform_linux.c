#include "test_platform.h"

#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/udp/epoll/nm_epoll.h>

void test_platform_init(struct test_platform* tp)
{
    struct np_platform* pl = &tp->pl;
    np_platform_init(pl);
    np_event_queue_init(pl, NULL, NULL);
    np_log_init();
    np_communication_buffer_init(pl);
    nm_unix_udp_epoll_init(pl);
    nm_unix_ts_init(pl);
    nm_unix_dns_init(pl);
    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
}


void test_platform_run(struct test_platform* tp)
{
    int nfds;
    while (true) {
        np_event_queue_execute_all(&tp->pl);
        if (np_event_queue_has_timed_event(&tp->pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&tp->pl);

            nfds = nm_epoll_timed_wait(ms);
        } else {
            nfds = nm_epoll_inf_wait();
        }
        nm_epoll_read(nfds);
    }
}
