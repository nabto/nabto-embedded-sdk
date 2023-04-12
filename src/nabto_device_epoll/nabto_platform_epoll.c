#include <api/nabto_device_platform.h>
#include <api/nabto_device_integration.h>

#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/mdns/nm_mdns_server.h>
#include <modules/communication_buffer/nm_communication_buffer.h>
#include <api/nabto_device_threads.h>

#include <modules/event_queue/thread_event_queue.h>

#include <platform/np_allocator.h>

#include <platform/np_logging.h>
#include <platform/np_logging_defines.h>

#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>

#include <modules/epoll/nm_epoll.h>
#include <modules/unix/nm_unix_local_ip.h>

#define LOG NABTO_LOG_MODULE_PLATFORM

/**
 * Structure containing all the platform adapter specific data.
 */
struct epoll_platform {
    struct nm_epoll epollContext;
    struct nm_unix_dns_resolver dnsResolver;

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
    
    // Create a new platform object. The platform is providing all the
    // functionality which can change between the nabto_device
    // implementations.

    struct epoll_platform* platform = np_calloc(1, sizeof(struct epoll_platform));
    if (platform == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    platform->coreMutex = eventMutex;

    struct np_timestamp timestamp = nm_unix_ts_get_impl();
    
    ec = nm_epoll_init(&platform->epollContext, eventMutex, timestamp);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    // Create libevent based implementations of udp, tcp, dns,
    // timestamp and local ip functionalities.
    struct np_udp udp = nm_epoll_udp_get_impl(&platform->epollContext);
    struct np_tcp tcp = nm_epoll_tcp_get_impl(&platform->epollContext);
    struct np_dns dns = nm_unix_dns_resolver_get_impl(&platform->dnsResolver);
    struct np_local_ip localIp = nm_unix_local_ip_get_impl(&platform->epollContext);


    // Create an event queue which is based on libevent.
    platform->eq = nm_epoll_event_queue_get_impl(&platform->epollContext);

    ec = nm_unix_dns_resolver_init(&platform->dnsResolver);

    if (ec != NABTO_EC_OK) {
        return ec;
    }


    // Create a mdns server
    // the mdns server requires special udp bind functions.
    struct nm_mdns_udp_bind mdnsUdpBind = nm_epoll_mdns_udp_bind_get_impl(&platform->epollContext);


    ec = nm_mdns_server_init(&platform->mdnsServer, &platform->eq, &udp, &mdnsUdpBind, &localIp);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    struct np_mdns mdnsImpl = nm_mdns_server_get_impl(&platform->mdnsServer);

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

    nm_unix_dns_resolver_run(&platform->dnsResolver);



    ec = nm_epoll_run(&platform->epollContext);
    return ec;
}

void nabto_device_platform_close(struct nabto_device_context* device, struct np_completion_event* event)
{
    struct epoll_platform* platform = nabto_device_integration_get_platform_data(device);

    nm_mdns_server_close(&platform->mdnsServer, event);
}

void nabto_device_platform_deinit(struct nabto_device_context* device)
{
    struct epoll_platform* platform = nabto_device_integration_get_platform_data(device);

    if (platform == NULL) {
        return;
    }
    nabto_device_threads_mutex_lock(platform->coreMutex);
    nm_mdns_server_deinit(&platform->mdnsServer);
    nabto_device_threads_mutex_unlock(platform->coreMutex);
    nm_unix_dns_resolver_deinit(&platform->dnsResolver);
    nm_epoll_deinit(&platform->epollContext);
    np_free(platform);
}


void nabto_device_platform_stop_blocking(struct nabto_device_context* device)
{
    struct epoll_platform* platform = nabto_device_integration_get_platform_data(device);
    nm_epoll_stop_blocking(&platform->epollContext);
}
