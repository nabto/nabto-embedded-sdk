#include <api/nabto_device_platform.h>
#include <api/nabto_device_integration.h>

#include "libevent_event_queue.h"

#include <modules/libevent/nm_libevent.h>
#include <modules/libevent/nm_libevent_dns.h>
#include <modules/libevent/nm_libevent_mdns_udp_bind.h>

#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/mdns/nm_mdns_server.h>
#include <modules/communication_buffer/nm_communication_buffer.h>
#include <api/nabto_device_threads.h>

#include <event.h>
#include <event2/event.h>
#include <event2/thread.h>

#include <modules/event_queue/thread_event_queue.h>

#include <platform/np_allocator.h>

#define LOG NABTO_LOG_MODULE_PLATFORM

#include <platform/np_logging.h>
#include <platform/np_logging_defines.h>

#define LOG NABTO_LOG_MODULE_PLATFORM

static void* libevent_thread(void* data);
static bool libevent_do_one(struct event_base* eventBase);

/**
 * Structure containing all the platform adapter specific data.
 */
struct libevent_platform {
    struct event_base* eventBase;
    struct nm_libevent_context libeventContext;
    struct nm_libevent_dns libeventDns;

    struct nabto_device_thread* libeventThread;
    struct thread_event_queue threadEventQueue;
    bool stopped;

    // Store a reference to the event queue as it needs special destruction.
    struct np_event_queue eq;

    struct nm_mdns_server mdnsServer;
    struct nabto_device_mutex* coreMutex;
};



/**
 * This function is called from nabto_device_new.
 */
np_error_code nabto_device_platform_init(struct nabto_device_context* device, struct nabto_device_mutex* eventMutex)
{
    np_error_code ec;
    NABTO_LOG_TRACE(LOG, "initializing platform");
    // Initialize the global libevent context.
    nm_libevent_global_init();

    // Create a new platform object. The platform is providing all the
    // functionality which can change between the nabto_device
    // implementations.

    struct libevent_platform* platform = np_calloc(1, sizeof(struct libevent_platform));
    if (platform == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    platform->coreMutex = eventMutex;

    platform->eventBase = event_base_new();
    if (platform->eventBase == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    // The libevent module comes with UDP, TCP, local ip and timestamp
    // module implementations.
    if (!nm_libevent_init(&platform->libeventContext, platform->eventBase)) {
        return NABTO_EC_FAILED;
    }

    // Create libevent based implementations of udp, tcp, dns,
    // timestamp and local ip functionalities.
    struct np_udp udp = nm_libevent_udp_get_impl(&platform->libeventContext);
    struct np_tcp tcp = nm_libevent_tcp_get_impl(&platform->libeventContext);
    struct np_timestamp timestamp = nm_libevent_timestamp_get_impl(&platform->libeventContext);
    struct np_dns dns = nm_libevent_dns_get_impl(&platform->libeventDns);
    struct np_local_ip localIp = nm_libevent_local_ip_get_impl(&platform->libeventContext);

    ec = thread_event_queue_init(&platform->threadEventQueue, eventMutex, &timestamp);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    // Create an event queue which is based on libevent.
    platform->eq = thread_event_queue_get_impl(&platform->threadEventQueue);

    ec = nm_libevent_dns_init(&platform->libeventDns, platform->eventBase, eventMutex, &platform->eq);

    if (ec != NABTO_EC_OK) {
        return ec;
    }


    // Create a mdns server
    // the mdns server requires special udp bind functions.
    struct nm_mdns_udp_bind mdnsUdpBind = nm_libevent_mdns_udp_bind_get_impl(&platform->libeventContext);


    ec = nm_mdns_server_init(&platform->mdnsServer, &platform->eq, &udp, &mdnsUdpBind, &localIp);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    struct np_mdns mdnsImpl = nm_mdns_server_get_impl(&platform->mdnsServer);

    // Start the thread where the libevent main loop runs.
    platform->libeventThread = nabto_device_threads_create_thread();
    if (platform->libeventThread == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    ec = nabto_device_threads_run(platform->libeventThread, libevent_thread, platform);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    /**
     * Store a pointer to the libevent_platform in the device, such
     * that it can be retrieved in later lifecycle events.
     */
    nabto_device_integration_set_platform_data(device, platform);

    /**
     * Tell the device which implementations of the functionalities it
     * should use.
     */
    nabto_device_integration_set_udp_impl(device, &udp);
    nabto_device_integration_set_tcp_impl(device, &tcp);
    nabto_device_integration_set_timestamp_impl(device, &timestamp);
    nabto_device_integration_set_dns_impl(device, &dns);
    nabto_device_integration_set_event_queue_impl(device, &platform->eq);
    nabto_device_integration_set_local_ip_impl(device, &localIp);
    nabto_device_integration_set_mdns_impl(device, &mdnsImpl);

    ec = thread_event_queue_run(&platform->threadEventQueue);
    return ec;
}

void nabto_device_platform_close(struct nabto_device_context* device, struct np_completion_event* event)
{
    struct libevent_platform* platform = nabto_device_integration_get_platform_data(device);

    nm_mdns_server_close(&platform->mdnsServer, event);
}

void nabto_device_platform_deinit(struct nabto_device_context* device)
{
    struct libevent_platform* platform = nabto_device_integration_get_platform_data(device);

    if (platform == NULL) {
        return;
    }
    nm_mdns_server_deinit(&platform->mdnsServer);

    thread_event_queue_deinit(&platform->threadEventQueue);
    nabto_device_threads_free_thread(platform->libeventThread);
    nm_libevent_dns_deinit(&platform->libeventDns);
    nm_libevent_deinit(&platform->libeventContext);

    event_base_free(platform->eventBase);
    nm_libevent_global_deinit();
    np_free(platform);
}

static size_t maxExtraEvents = 1000; // ensure that the stop loop does not block forever.

void nabto_device_platform_stop_blocking(struct nabto_device_context* device)
{
    struct libevent_platform* platform = nabto_device_integration_get_platform_data(device);
    if (platform == NULL) {
        return;
    }
    if (platform->stopped) {
        return;
    }
    nm_mdns_server_stop(&platform->mdnsServer);
    nm_libevent_dns_stop(&platform->libeventDns);
    nm_libevent_stop(&platform->libeventContext);
    platform->stopped = true;
    event_base_loopbreak(platform->eventBase);
    nabto_device_threads_join(platform->libeventThread);
    thread_event_queue_stop_blocking(&platform->threadEventQueue);

    // run single libevent and thread_event_queue events until there's no more events.
    for (int i = 0; i < maxExtraEvents; i++) {
        bool more = thread_event_queue_do_one(&platform->threadEventQueue) || libevent_do_one(platform->eventBase);
        if (!more) {
            break;
        }
    }
}

#include <signal.h>

bool libevent_do_one(struct event_base* eventBase)
{
    int ec = event_base_loop(eventBase, EVLOOP_ONCE | EVLOOP_NONBLOCK);
    if (ec == 0) {
        // if we handled atleast one event
        return true;
    }
    return false;
}

/*
 * Thread running the network
 */
void* libevent_thread(void* data)
{
    struct libevent_platform* platform = data;
    if (platform->stopped == true) {
        return NULL;
    }

#ifdef HAVE_PTHREAD_H
#ifndef SO_NOSIGPIPE
    // On Linux we block TCP SIGPIPE on the thread as POSIX.1-2004 or later requires it to be
    // delivered to the offending thread. Linux with POSIX.1-2001 or earlier can cause SIGPIPE.
    // Mac uses the SO_NOSIGPIPE socket option at socket creation.
    sigset_t set;
    int s;

    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    s = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (s != 0) {
        NABTO_LOG_ERROR( NABTO_LOG_MODULE_EVENT_QUEUE, "Failed to create sigmask: %d", s);
    }
#endif
#endif
    event_base_loop(platform->eventBase, 0);
    return NULL;
}
