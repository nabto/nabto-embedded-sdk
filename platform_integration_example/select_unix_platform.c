#include <api/nabto_device_platform.h>
#include <api/nabto_device_threads.h>
//#include <api/nabto_device_default_modules.h>

#include "select_unix_event_queue.h"



#include <modules/select_unix/nm_select_unix.h>
#include <modules/event_queue/nm_event_queue.h>
#include <modules/logging/api/nm_api_logging.h>
#include <modules/mbedtls/nm_mbedtls_random.h>
#include <modules/mbedtls/nm_mbedtls_srv.h>
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/mdns/nm_mdns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/dns/unix/nm_unix_dns.h>

#include <stddef.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

static void* network_thread(void* data);

struct select_unix_platform
{
    struct np_platform* pl;
    struct nabto_device_thread* networkThread;
    struct nabto_device_mutex* mutex;
    struct nm_select_unix selectUnix;
    struct select_unix_event_queue eventQueue;
    bool stopped;
};

np_error_code nabto_device_default_modules_init(struct np_platform* pl)
{
    nm_api_log_init();
    np_communication_buffer_init(pl);
    nm_mbedtls_cli_init(pl);
    nm_mbedtls_srv_init(pl);
    nm_mbedtls_random_init(pl);

    return NABTO_EC_OK;
}


void nabto_device_default_modules_deinit(struct np_platform* pl)
{
    nm_mbedtls_random_deinit(pl);
}

np_error_code nabto_device_init_platform(struct np_platform* pl, struct nabto_device_mutex* eventMutex)
{
    struct select_unix_platform* platform = calloc(1, sizeof(struct select_unix_platform));
    platform->pl = pl;
    platform->mutex = eventMutex;
    platform->stopped = false;
    pl->platformData = platform;

    // There are some default modules these includes at the time
    // beeing logging, communication buffers, dtls server, dtls
    // client, mdns server, mbedtls based random module. All these
    // modules is initialized by the following function.
    np_error_code ec;
    ec = nabto_device_default_modules_init(pl);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    nm_mdns_init(pl);
    nm_unix_ts_init(pl);
    nm_unix_dns_init(pl);

    // This one initializes both the udp and tcp module.
    nm_select_unix_init(&platform->selectUnix, pl);

    select_unix_event_queue_init(&platform->eventQueue, pl, eventMutex);

    platform->networkThread = nabto_device_threads_create_thread();
    if (nabto_device_threads_run(platform->networkThread, network_thread, platform) != 0) {
        // TODO
    }
    return NABTO_EC_OK;
}


void nabto_device_deinit_platform(struct np_platform* pl)
{
    struct select_unix_platform* platform = pl->platformData;
    select_unix_event_queue_deinit(&platform->eventQueue);

    nabto_device_default_modules_deinit(pl);

    nabto_device_threads_free_thread(platform->networkThread);
    free(platform);
}

void nabto_device_platform_stop_blocking(struct np_platform* pl)
{
    struct select_unix_platform* platform = pl->platformData;
    platform->stopped = true;
    nm_select_unix_notify(&platform->selectUnix);
    nabto_device_threads_join(platform->networkThread);
    nm_select_unix_notify(&platform->selectUnix);
    select_unix_event_queue_stop_blocking(&platform->eventQueue);

    nm_select_unix_close(&platform->selectUnix);

}

void* network_thread(void* data)
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
