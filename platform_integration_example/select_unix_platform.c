#include <api/nabto_device_platform.h>
#include <api/nabto_device_threads.h>
#include <api/nabto_device_integration.h>

#include "select_unix_event_queue.h"



#include <modules/select_unix/nm_select_unix.h>
#include <modules/select_unix/nm_select_unix_udp.h>
#include <modules/select_unix/nm_select_unix_tcp.h>
#include <modules/event_queue/nm_event_queue.h>
#include <modules/mbedtls/nm_mbedtls_random.h>
#include <modules/mbedtls/nm_mbedtls_srv.h>
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/mdns/nm_mdns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/unix/nm_unix_local_ip.h>
#include <modules/communication_buffer/nm_communication_buffer.h>

#include <platform/np_tcp.h>

#include <stddef.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

static void* network_thread(void* data);

struct select_unix_platform
{
    /**
     * a reference to the platform. The np_platform is owned by the NabtoDevice object.
     */
    struct np_platform* pl;

    /**
     * The network thread is used for running the select loop.
     */
    struct nabto_device_thread* networkThread;

    /**
     * This mutex is used for protecting the system such that only one
     * thread can make calls to the core at a time.
     */
    struct nabto_device_mutex* mutex;

    /**
     * The select unix module.
     */
    struct nm_select_unix selectUnix;

    /**
     * The select unix event queue which is implemented specifically
     * for this implementation. The purpose of the event queue is to
     * execute events.
     */
    struct select_unix_event_queue eventQueue;

    /**
     * Stopped bit if true the platform has been stopped and the
     * network thread should stop its event loop.
     */
    bool stopped;
};

/**
 * This function is called when nabto_device_new is invoked. This
 * function should initialize all the platform modules whis is needed
 * to create a functional platform for the device. See
 * <platform/np_platform.h> for a list of modules required for a
 * platform.
 */
np_error_code nabto_device_platform_init(struct nabto_device_context* device, struct nabto_device_mutex* eventMutex)
{
    struct select_unix_platform* platform = calloc(1, sizeof(struct select_unix_platform));
    platform->mutex = eventMutex;
    platform->stopped = false;

    nabto_device_integration_set_platform_data(device, platform);

    nm_select_unix_init(&platform->selectUnix);

    struct np_udp udpImpl = nm_select_unix_udp_get_impl(&platform->selectUnix);
    struct np_tcp tcpImpl = nm_select_unix_tcp_get_impl(&platform->selectUnix);
    //struct np_tcp tcpImpl = nm_select_unix_tcp_get_impl(&platform->selectUnix);
    struct np_dns dnsImpl = nm_unix_dns_create();
    struct np_timestamp timestampImpl = nm_unix_ts_create();
    struct np_local_ip localIpImpl = nm_unix_local_ip_get_impl();

    nabto_device_integration_set_udp_impl(device, &udpImpl);
    nabto_device_integration_set_tcp_impl(device, &tcpImpl);
    nabto_device_integration_set_timestamp_impl(device, &timestampImpl);
    nabto_device_integration_set_dns_impl(device, &dnsImpl);
    nabto_device_integration_set_local_ip_impl(device, &localIpImpl);

    // This platform integration uses the following event queue. The
    // event queue executes events and allow events to be posted to
    // it.
    struct np_event_queue eventQueueImpl = select_unix_event_queue_init(&platform->eventQueue, eventMutex, &timestampImpl);

    nabto_device_integration_set_event_queue_impl(device, &eventQueueImpl);

    platform->networkThread = nabto_device_threads_create_thread();
    if (nabto_device_threads_run(platform->networkThread, network_thread, platform) != 0) {
        // TODO
    }
    return NABTO_EC_OK;
}

/**
 * This function is called from nabto_device_free.
 */
void nabto_device_platform_deinit(struct nabto_device_context* device)
{

    struct select_unix_platform* platform = nabto_device_integration_get_platform_data(device);
    select_unix_event_queue_deinit(&platform->eventQueue);
    nabto_device_threads_free_thread(platform->networkThread);
    free(platform);
}

/**
 * This function is called from nabto_device_stop or nabto_device_free
 * if the device is freed without being stopped first.
 */
void nabto_device_platform_stop_blocking(struct nabto_device_context* device)
{
    struct select_unix_platform* platform = nabto_device_integration_get_platform_data(device);
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
            return NULL;
        } else {
            // Wait for events.
            nfds = nm_select_unix_inf_wait(&platform->selectUnix);
            nm_select_unix_read(&platform->selectUnix, nfds);
        }
    }
    return NULL;
}
