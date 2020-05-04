#include <api/nabto_platform.h>

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

struct event_base* eventBase;
struct event* signalEvent;
struct nm_libevent_context libeventContext;

struct nabto_device_thread* networkThread;

static bool stopped = false;

static void nabto_device_signal_event(evutil_socket_t s, short event, void* userData);
static void* nabto_device_platform_network_thread(void* data);

void nabto_device_init_platform(struct np_platform* pl)
{
    np_platform_init(pl);
    nm_libevent_global_init();
    eventBase = event_base_new();
    signalEvent = event_new(eventBase, -1, 0, &nabto_device_signal_event, NULL);
    nm_api_log_init();


}

void nabto_device_deinit_platform(struct np_platform* pl)
{
    event_free(signalEvent);
    event_base_free(eventBase);
    np_platform_deinit(pl);
    nm_libevent_global_deinit();
}

np_error_code nabto_device_init_platform_modules(struct np_platform* pl)
{
    np_communication_buffer_init(pl);
    nm_libevent_init(pl, &libeventContext, eventBase);

    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
    nm_mdns_init(pl);
    nm_random_init(pl);

    networkThread = nabto_device_threads_create_thread();
    if (nabto_device_threads_run(networkThread, nabto_device_platform_network_thread, eventBase) != 0) {
        // TODO
    }

    return NABTO_EC_OK;
}

void nabto_device_deinit_platform_modules(struct np_platform* pl)
{
    nm_random_deinit(pl);
    nm_libevent_deinit(&libeventContext);
    nabto_device_threads_free_thread(networkThread);
}

void nabto_device_platform_stop_blocking(struct np_platform* pl)
{
    if (stopped) {
        return;
    }
    stopped = true;
    event_active(signalEvent, 0, 0);
    nabto_device_threads_join(networkThread);
}

/*
 * Thread running the network
 */
void* nabto_device_platform_network_thread(void* data)
{
    struct event_base* eventBase = data;
    if (stopped == true) {
        return NULL;
    }
    event_base_loop(eventBase, EVLOOP_NO_EXIT_ON_EMPTY);
    return NULL;
}

void nabto_device_signal_event(evutil_socket_t s, short event, void* userData)
{
    event_base_loopbreak(eventBase);
}
