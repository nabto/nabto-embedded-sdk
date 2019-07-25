#include <modules/mdns/nm_mdns.h>

#include <platform/np_platform.h>
#include <platform/np_logging.h>
#include <platform/np_timestamp.h>

#include <stdio.h>

const char* productId = "pr-test";
const char* deviceId = "de-test";
const uint16_t port = 1234;

void mdns_started(const np_error_code ec, void* userData)
{
    printf("Started %d\n", ec);
}

int main(int argc, char** argv)
{
    struct nm_mdns mdns;

    struct np_platform pl;
    int nfds;
    np_platform_init(&pl);
    np_event_queue_init(&pl, NULL, NULL);
    np_communication_buffer_init(&pl);
    np_udp_init(&pl);
    np_ts_init(&pl);

    np_log_init();

    nm_mdns_init(&mdns, &pl, productId, deviceId, port);

    nm_mdns_async_start(&mdns, mdns_started, NULL);

    while (true) {
        np_event_queue_execute_all(&pl);
        NABTO_LOG_INFO(0, "before epoll wait %i", np_event_queue_has_ready_event(&pl));
        if (np_event_queue_has_timed_event(&pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&pl);
            nfds = pl.udp.timed_wait(ms);
        } else {
            nfds = pl.udp.inf_wait();
        }
        if (nfds > 0) {
            pl.udp.read(nfds);
        }
    }

    nm_mdns_deinit(&mdns);
}
