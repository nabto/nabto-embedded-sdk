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

#include <stddef.h>
#include <stdlib.h>

static void* core_thread(void* data);

struct select_unix_platform
{
    struct nabto_device_thread* coreThread;
    struct nm_select_unix selectUnix;
    struct nm_event_queue eventQueue;
};

np_error_code nabto_device_init_platform(struct np_platform* pl, struct nabto_device_mutex* eventMutex)
{
    struct select_unix_platform* platform = calloc(1, sizeof(struct select_unix_platform));
    pl->platformData = platform;
    nm_api_log_init();
    np_communication_buffer_init(pl);
    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
    nm_mdns_init(pl);
    nm_random_init(pl);

    nm_select_unix_init(&platform->selectUnix, pl);

    select_unix_event_queue_init(platform, pl);
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
    nm_select_unix_close(&platform->selectUnix);
    nabto_device_threads_join(platform->coreThread);
}

void* core_thread(void* data)
{
    struct select_unix_platform* platform = data;
    while(true) {

        // run all events
        // run all timed events
        // wait for next timed event to expire or wait infinite.

        int nfds;
        nfds = nm_select_unix_inf_wait(&platform->selectUnix);
        nm_select_unix_read(&platform->selectUnix, nfds);
    }
    return NULL;
}
