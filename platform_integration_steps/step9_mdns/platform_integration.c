#include <api/nabto_device_platform.h>
#include <api/nabto_device_integration.h>

#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/event_queue/thread_event_queue.h>
#include <modules/dns/unix/nm_unix_dns.h>
#include <modules/select_unix/nm_select_unix.h>
#include <modules/unix/nm_unix_local_ip.h>
#include <modules/mdns/nm_mdns_server.h>
#include <modules/select_unix/nm_select_unix_mdns_udp_bind.h>

#include <stdlib.h>

struct platform_data {
    struct thread_event_queue eventQueue;
    struct nm_unix_dns_resolver dnsResolver;
    struct nm_select_unix networking;
    struct nm_mdns_server mdnsServer;
};

np_error_code nabto_device_platform_init(struct nabto_device_context* device, struct nabto_device_mutex* coreMutex)
{
    struct platform_data* platform = calloc(1, sizeof(struct platform_data));

    // Create a new instance of the unix timestamp module implementation.
    struct np_timestamp timestampImpl = nm_unix_ts_get_impl();


    // Initialize a the eventQueue, the thread event queue depends on
    // the timestamp module. so that module is given as an argument.
    thread_event_queue_init(&platform->eventQueue, coreMutex, &timestampImpl);
    thread_event_queue_run(&platform->eventQueue);

    struct np_event_queue eventQueueImpl = thread_event_queue_get_impl(&platform->eventQueue);

    // Use the unix dns module.

    nm_unix_dns_resolver_init(&platform->dnsResolver);
    nm_unix_dns_resolver_run(&platform->dnsResolver);
    struct np_dns dnsImpl = nm_unix_dns_resolver_get_impl(&platform->dnsResolver);

    // Use the select unix networking module.
    nm_select_unix_init(&platform->networking);
    nm_select_unix_run(&platform->networking);
    struct np_udp udpImpl = nm_select_unix_udp_get_impl(&platform->networking);
    struct np_tcp tcpImpl = nm_select_unix_tcp_get_impl(&platform->networking);

    // Use the unix based local ip implementation.
    struct np_local_ip localIpImpl = nm_unix_local_ip_get_impl();

    // Use the mdns server provided by nabto for the device. This mdns
    // server implementation needs a few extra udp functions for
    // binding udp sockets to the MDNS multicast groups. this
    // functionality is enclosed inside the `struct nm_mdns_udp_bind`
    // interface.
    struct nm_mdns_udp_bind mdnsUdpBindImpl = nm_select_unix_mdns_udp_bind_get_impl(&platform->networking);

    nm_mdns_server_init(&platform->mdnsServer, &eventQueueImpl, &udpImpl, &mdnsUdpBindImpl, &localIpImpl);
    struct np_mdns mdnsImpl = nm_mdns_server_get_impl(&platform->mdnsServer);

    // set the implementations in the device such that they can be
    // used by the device api.
    nabto_device_integration_set_timestamp_impl(device, &timestampImpl);
    nabto_device_integration_set_event_queue_impl(device, &eventQueueImpl);
    nabto_device_integration_set_dns_impl(device, &dnsImpl);
    nabto_device_integration_set_udp_impl(device, &udpImpl);
    nabto_device_integration_set_tcp_impl(device, &tcpImpl);
    nabto_device_integration_set_local_ip_impl(device, &localIpImpl);
    nabto_device_integration_set_mdns_impl(device, &mdnsImpl);


    nabto_device_integration_set_platform_data(device, platform);

    return NABTO_EC_OK;
}
void nabto_device_platform_deinit(struct nabto_device_context* device)
{
    struct platform_data* platform = nabto_device_integration_get_platform_data(device);

    nm_mdns_server_deinit(&platform->mdnsServer);

    nm_unix_dns_resolver_deinit(&platform->dnsResolver);

    thread_event_queue_deinit(&platform->eventQueue);

}
void nabto_device_platform_stop_blocking(struct nabto_device_context* device)
{
    struct platform_data* platform = nabto_device_integration_get_platform_data(device);

    nm_mdns_server_stop(&platform->mdnsServer);

    // The event queue needs to be stopped, but we need to wait for
    // outstanding events to be finished first, hence the blocking
    // nature of the call.
    thread_event_queue_stop_blocking(&platform->eventQueue);
}
