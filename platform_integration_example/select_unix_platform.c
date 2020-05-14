#include <api/nabto_device_platform.h>
#include <api/nabto_device_threads.h>

#include "select_unix_event_queue.h"



#include <modules/select_unix/nm_select_unix.h>
#include <modules/event_queue/nm_event_queue.h>
#include <modules/logging/api/nm_api_logging.h>
#include <modules/dtls/nm_random.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/mdns/nm_mdns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/dns/unix/nm_unix_dns.h>

#include <stddef.h>
#include <stdlib.h>

static void* core_thread(void* data);

struct select_unix_platform
{
    struct np_platform* pl;
    struct nabto_device_thread* coreThread;
    struct nabto_device_mutex* mutex;
    struct nm_select_unix selectUnix;
    struct nm_event_queue eventQueue;
    bool stopped;
};

np_error_code nabto_device_init_platform(struct np_platform* pl, struct nabto_device_mutex* eventMutex)
{
    struct select_unix_platform* platform = calloc(1, sizeof(struct select_unix_platform));
    platform->pl = pl;
    platform->mutex = eventMutex;
    platform->stopped = false;
    pl->platformData = platform;
    nm_api_log_init();
    np_communication_buffer_init(pl);
    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
    nm_mdns_init(pl);
    nm_random_init(pl);
    nm_unix_ts_init(pl);
    nm_unix_dns_init(pl);

    nm_select_unix_init(&platform->selectUnix, pl);

    select_unix_event_queue_init(&platform->eventQueue, pl);
    platform->coreThread = nabto_device_threads_create_thread();
    if (nabto_device_threads_run(platform->coreThread, core_thread, platform) != 0) {
        // TODO
    }
    return NABTO_EC_OK;
}


void nabto_device_deinit_platform(struct np_platform* pl)
{
}

void nabto_device_platform_stop_blocking(struct np_platform* pl)
{
    struct select_unix_platform* platform = pl->platformData;
    platform->stopped = true;
    nm_select_unix_close(&platform->selectUnix);
    nabto_device_threads_join(platform->coreThread);
}

void* core_thread(void* data)
{
    struct select_unix_platform* platform = data;

    while(true) {
        uint32_t nextEvent;
        uint32_t now = np_timestamp_now_ms(platform->pl);
        int nfds;
        nabto_device_threads_mutex_lock(platform->mutex);
        if (nm_event_queue_run_event(&platform->eventQueue)) {
            // Run the loop again to see if there's more events ready.
            nabto_device_threads_mutex_unlock(platform->mutex);
        } else if (nm_event_queue_run_timed_event(&platform->eventQueue, now)) {
            // Run the loop again to see if there's more events ready.
            nabto_device_threads_mutex_unlock(platform->mutex);
        } else if (nm_event_queue_next_timed_event(&platform->eventQueue, &nextEvent)) {
            // There is a timed event in the future lets wait for it
            // or some network traffic or some other event.

            nabto_device_threads_mutex_unlock(platform->mutex);
            int32_t diff = np_timestamp_difference(nextEvent, now);
            nfds = nm_select_unix_timed_wait(&platform->selectUnix, diff);
        } else if (platform->stopped) {
            // There is no pending events or timed events and the
            // platform is stopped, lets exit.
            nabto_device_threads_mutex_unlock(platform->mutex);
            return NULL;
        } else {
            // There is no events or timed events and we are not
            // stopped.
            nabto_device_threads_mutex_unlock(platform->mutex);
            nfds = nm_select_unix_inf_wait(&platform->selectUnix);
            nm_select_unix_read(&platform->selectUnix, nfds);
        }
    }
    return NULL;
}


void select_unix_notify_platform(void* data)
{
    struct select_unix_platform* platform = data;
    nm_select_unix_notify(&platform->selectUnix);
}
