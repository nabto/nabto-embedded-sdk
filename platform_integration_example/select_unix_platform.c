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

#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

static void* core_thread(void* data);

struct select_unix_platform
{
    struct np_platform* pl;
    struct nabto_device_thread* coreThread;
    struct nabto_device_mutex* mutex;
    struct nm_select_unix selectUnix;
    struct select_unix_event_queue eventQueue;
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

    select_unix_event_queue_init(&platform->eventQueue, pl, eventMutex);

    platform->coreThread = nabto_device_threads_create_thread();
    if (nabto_device_threads_run(platform->coreThread, core_thread, platform) != 0) {
        // TODO
    }
    return NABTO_EC_OK;
}


void nabto_device_deinit_platform(struct np_platform* pl)
{
    struct select_unix_platform* platform = pl->platformData;
    select_unix_event_queue_deinit(&platform->eventQueue);
}

void nabto_device_platform_stop_blocking(struct np_platform* pl)
{
    struct select_unix_platform* platform = pl->platformData;
    platform->stopped = true;
    nm_select_unix_notify(&platform->selectUnix);
    nabto_device_threads_join(platform->coreThread);
    nm_select_unix_notify(&platform->selectUnix);
    select_unix_event_queue_stop_blocking(&platform->eventQueue);

    nm_select_unix_close(&platform->selectUnix);

}

void* core_thread(void* data)
{
    struct select_unix_platform* platform = data;

    while(true) {
        int nfds;

        if (platform->stopped) {
            // There is no pending events or timed events and the
            // platform is stopped, lets exit.
            return NULL;
        } else {
            // There is no events or timed events and we are not
            // stopped.
            nfds = nm_select_unix_inf_wait(&platform->selectUnix);
            nm_select_unix_read(&platform->selectUnix, nfds);
        }
    }
    return NULL;
}
