#include "test_platform.h"

#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/select_unix/nm_select_unix.h>
#include <modules/mdns/nm_mdns.h>
#include <modules/logging/test/nm_logging_test.h>

struct nm_select_unix ctx;

void test_platform_init(struct test_platform* tp)
{
    struct np_platform* pl = &tp->pl;
    np_platform_init(pl);
    np_event_queue_init(pl, NULL, NULL);
    nm_logging_test_init();
    np_communication_buffer_init(pl);
    nm_select_unix_init(&ctx, pl);
    nm_unix_ts_init(pl);
    nm_unix_dns_init(pl);
    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
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

            nfds = nm_select_unix_timed_wait(&ctx, ms);
        } else {
            nfds = nm_select_unix_inf_wait(&ctx);
        }
        nm_select_unix_read(&ctx, nfds);
    }
}

void test_platform_stop(struct test_platform* tp)
{
    tp->stopped = true;
    nm_select_unix_break_wait(&ctx);
}
