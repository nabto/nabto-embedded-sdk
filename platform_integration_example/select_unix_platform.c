#include <api/nabto_device_platform.h>
#include <api/nabto_device_threads.h>
#include <api/nabto_device_integration.h>

#include <modules/select_unix/nm_select_unix.h>
#include <modules/select_unix/nm_select_unix_mdns_udp_bind.h>
#include <modules/event_queue/thread_event_queue.h>
#include <modules/mbedtls/nm_mbedtls_srv.h>
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/mdns/nm_mdns_server.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/unix/nm_unix_local_ip.h>
#include <modules/communication_buffer/nm_communication_buffer.h>

#ifdef NABTO_USE_MBEDTLS
#include <modules/mbedtls/nm_mbedtls_random.h>
#endif
#ifdef NABTO_USE_WOLFSSL
#include <modules/wolfssl/nm_wolfssl_random.h>
#endif

#include <stddef.h>
#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

struct select_unix_platform
{
    /**
     * The select unix module.
     */
    struct nm_select_unix selectUnix;

    /**
     * The select unix event queue which is implemented specifically
     * for this implementation. The purpose of the event queue is to
     * execute events.
     */
    struct thread_event_queue eventQueue;

    /**
     * Context for the dns resolver
     */
    struct nm_unix_dns_resolver dnsResolver;

    /**
     * Mdns server context
     */
    struct nm_mdns_server mdnsServer;

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
np_error_code nabto_device_platform_init(struct nabto_device_context* device, struct nabto_device_mutex* coreMutex)
{
    struct select_unix_platform* platform = calloc(1, sizeof(struct select_unix_platform));
    platform->stopped = false;

    /**
     * The folloing section initializes the modules which implements
     * needed interfaces for the device.
     */
    nm_select_unix_init(&platform->selectUnix);

    // Further the select_unix module needs to be run by a thread
    nm_select_unix_run(&platform->selectUnix);

    nm_unix_dns_resolver_init(&platform->dnsResolver);
    nm_unix_dns_resolver_run(&platform->dnsResolver);

    struct np_udp udpImpl = nm_select_unix_udp_get_impl(&platform->selectUnix);
    struct np_tcp tcpImpl = nm_select_unix_tcp_get_impl(&platform->selectUnix);
    struct np_dns dnsImpl = nm_unix_dns_resolver_get_impl(&platform->dnsResolver);
    struct np_timestamp timestampImpl = nm_unix_ts_get_impl();
    struct np_local_ip localIpImpl = nm_unix_local_ip_get_impl();

    // This platform integration uses the following event queue. The
    // event queue executes events and allow events to be posted to
    // it. The event queue depends on the timestamp implementation hence it is
    // initialized a bit later.
    thread_event_queue_init(&platform->eventQueue, coreMutex, &timestampImpl);
    thread_event_queue_run(&platform->eventQueue);
    struct np_event_queue eventQueueImpl = thread_event_queue_get_impl(&platform->eventQueue);

    // Create a mdns server. The mdns server depends on the event
    // queue, udp and local ip implementations.

    struct nm_mdns_udp_bind mdnsUdpBindImpl = nm_select_unix_mdns_udp_bind_get_impl(&platform->selectUnix);

    nm_mdns_server_init(&platform->mdnsServer, &eventQueueImpl, &udpImpl, &mdnsUdpBindImpl, &localIpImpl);
    struct np_mdns mdnsImpl = nm_mdns_server_get_impl(&platform->mdnsServer);

    /**
     * Store a pointer to the specific platform integration inside the
     * device, such that it can be retrieved and used in the
     * nabto_device_platform_deinit and
     * nabto_device_platform_stop_blocking functions.
     */
    nabto_device_integration_set_platform_data(device, platform);

    /**
     * The following code sets the different interface implemetations
     * into the device. The structs are being copied.
     */
    nabto_device_integration_set_udp_impl(device, &udpImpl);
    nabto_device_integration_set_tcp_impl(device, &tcpImpl);
    nabto_device_integration_set_timestamp_impl(device, &timestampImpl);
    nabto_device_integration_set_dns_impl(device, &dnsImpl);
    nabto_device_integration_set_local_ip_impl(device, &localIpImpl);
    nabto_device_integration_set_mdns_impl(device, &mdnsImpl);
    nabto_device_integration_set_event_queue_impl(device, &eventQueueImpl);

    return NABTO_EC_OK;
}

/**
 * This function is called from nabto_device_free.
 */
void nabto_device_platform_deinit(struct nabto_device_context* device)
{
    struct select_unix_platform* platform = nabto_device_integration_get_platform_data(device);
    nm_mdns_server_deinit(&platform->mdnsServer);
    thread_event_queue_deinit(&platform->eventQueue);
    nm_unix_dns_resolver_deinit(&platform->dnsResolver);
    nm_select_unix_deinit(&platform->selectUnix);
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
    nm_mdns_server_stop(&platform->mdnsServer);
    nm_select_unix_stop(&platform->selectUnix);
    thread_event_queue_stop_blocking(&platform->eventQueue);
}
