#include <api/nabto_device_platform.h>
#include <api/nabto_device_integration.h>

#include "libevent_event_queue.h"

#include <modules/libevent/nm_libevent.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/mbedtls/nm_mbedtls_random.h>
#include <modules/mdns/nm_mdns.h>
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/mbedtls/nm_mbedtls_srv.h>
#include <modules/communication_buffer/nm_communication_buffer.h>
#include <api/nabto_device_threads.h>

#include <event.h>
#include <event2/event.h>
#include <event2/thread.h>

#include <stdlib.h>




static void nabto_device_signal_event(evutil_socket_t s, short event, void* userData);
static void* nabto_device_platform_network_thread(void* data);

/**
 * Structure containing all the platform adapter specific data.
 */
struct nabto_device_platform_libevent {
    struct event_base* eventBase;
    struct event* signalEvent;
    struct nm_libevent_context libeventContext;

    struct nabto_device_thread* networkThread;
    bool stopped;
    struct np_event_queue eq;
};

np_error_code nabto_device_platform_init(struct nabto_device_context* device, struct nabto_device_mutex* eventMutex)
{
    nm_libevent_global_init();

    struct nabto_device_platform_libevent* platform = calloc(1, sizeof(struct nabto_device_platform_libevent));


    platform->eventBase = event_base_new();
    platform->signalEvent = event_new(platform->eventBase, -1, 0, &nabto_device_signal_event, platform);

    // The libevent module comes with UDP, TCP, local ip and timestamp module implementations.
    nm_libevent_init(&platform->libeventContext, platform->eventBase);


    nabto_device_integration_set_platform_data(device, platform);

    struct np_udp udp = nm_libevent_create_udp(&platform->libeventContext);
    struct np_tcp tcp = nm_libevent_create_tcp(&platform->libeventContext);
    struct np_timestamp timestamp = nm_libevent_create_timestamp(&platform->libeventContext);
    struct np_dns dns = nm_libevent_create_dns(&platform->libeventContext);
    struct np_local_ip localIp = nm_libevent_create_local_ip(&platform->libeventContext);

    platform->eq = libevent_event_queue_create(platform->eventBase, eventMutex);

    nabto_device_integration_set_udp_impl(device, &udp);
    nabto_device_integration_set_tcp_impl(device, &tcp);
    nabto_device_integration_set_timestamp_impl(device, &timestamp);
    nabto_device_integration_set_dns_impl(device, &dns);
    nabto_device_integration_set_event_queue_impl(device, &platform->eq);
    nabto_device_integration_set_local_ip_impl(device, &localIp);

    // TODO
    //nabto_device_platform_adapter_set_system_information_impl(device, systemFunctions, systemImpl);

    platform->networkThread = nabto_device_threads_create_thread();
    if (nabto_device_threads_run(platform->networkThread, nabto_device_platform_network_thread, platform) != 0) {
        // TODO
    }

    return NABTO_EC_OK;
}

void nabto_device_platform_deinit(struct nabto_device_context* device)
{
    struct nabto_device_platform_libevent* platform = nabto_device_integration_get_platform_data(device);
    libevent_event_queue_destroy(&platform->eq);
    //nm_mbedtls_random_deinit(pl);
    nm_libevent_deinit(&platform->libeventContext);
    nabto_device_threads_free_thread(platform->networkThread);

    event_free(platform->signalEvent);
    event_base_free(platform->eventBase);
    nm_libevent_global_deinit();
    free(platform);
}

void nabto_device_platform_stop_blocking(struct nabto_device_context* device)
{
    struct nabto_device_platform_libevent* platform = nabto_device_integration_get_platform_data(device);
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
