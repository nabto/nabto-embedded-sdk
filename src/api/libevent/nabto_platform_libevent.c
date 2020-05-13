#include <api/nabto_device_platform.h>

#include "libevent_event_queue.h"

#include <modules/libevent/nm_libevent.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/dtls/nm_random.h>
#include <modules/mdns/nm_mdns.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/logging/api/nm_api_logging.h>
#include <api/nabto_device_threads.h>

#include <event.h>
#include <event2/event.h>
#include <event2/thread.h>

#include <stdlib.h>


static void nabto_device_signal_event(evutil_socket_t s, short event, void* userData);
static void* nabto_device_platform_network_thread(void* data);


struct nabto_device_platform_libevent {
    struct event_base* eventBase;
    struct event* signalEvent;
    struct nm_libevent_context libeventContext;

    struct nabto_device_thread* networkThread;

    bool stopped;
};

np_error_code nabto_device_init_platform(struct np_platform* pl, struct nabto_device_mutex* eventMutex)
{
    nm_libevent_global_init();

    struct nabto_device_platform_libevent* platform = calloc(1, sizeof(struct nabto_device_platform_libevent));

    pl->platformData = platform;
    platform->eventBase = event_base_new();
    platform->signalEvent = event_new(platform->eventBase, -1, 0, &nabto_device_signal_event, platform);
    nm_api_log_init();

    np_communication_buffer_init(pl);
    nm_libevent_init(pl, &platform->libeventContext, platform->eventBase);

    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
    nm_mdns_init(pl);
    nm_random_init(pl);

    libevent_event_queue_init(pl, platform->eventBase, eventMutex);

    platform->networkThread = nabto_device_threads_create_thread();
    if (nabto_device_threads_run(platform->networkThread, nabto_device_platform_network_thread, platform) != 0) {
        // TODO
    }

    return NABTO_EC_OK;
}

void nabto_device_deinit_platform(struct np_platform* pl)
{
    struct nabto_device_platform_libevent* platform = pl->platformData;
    libevent_event_queue_deinit(pl);
    nm_random_deinit(pl);
    nm_libevent_deinit(&platform->libeventContext);
    nabto_device_threads_free_thread(platform->networkThread);

    event_free(platform->signalEvent);
    event_base_free(platform->eventBase);
    nm_libevent_global_deinit();
    free(platform);
}

void nabto_device_platform_stop_blocking(struct np_platform* pl)
{
    struct nabto_device_platform_libevent* platform = pl->platformData;
    if (platform->stopped) {
        return;
    }
    platform->stopped = true;
    event_active(platform->signalEvent, 0, 0);
    nabto_device_threads_join(platform->networkThread);
}

/*
 * Thread running the network
 */
void* nabto_device_platform_network_thread(void* data)
{
    struct nabto_device_platform_libevent* platform = data;
    if (platform->stopped == true) {
        return NULL;
    }
    event_base_loop(platform->eventBase, EVLOOP_NO_EXIT_ON_EMPTY);
    return NULL;
}

void nabto_device_signal_event(evutil_socket_t s, short event, void* userData)
{
    struct nabto_device_platform_libevent* platform = userData;
    event_base_loopbreak(platform->eventBase);
}
