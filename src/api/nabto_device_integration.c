#include "nabto_device_integration.h"

#include "nabto_device_defines.h"

// Get the
void* nabto_device_integration_get_platform_data(struct nabto_device_context* device)
{
    return device->platformAdapter;
}

void nabto_device_integration_set_platform_data(struct nabto_device_context* device, void* adapter)
{
    device->platformAdapter = adapter;
}

void nabto_device_integration_set_udp_impl(struct nabto_device_context* device, struct np_udp* obj)
{
    device->pl.udp = *obj;
}

void nabto_device_integration_set_tcp_impl(struct nabto_device_context* device, struct np_tcp* obj)
{
    device->pl.tcp = *obj;
}

void nabto_device_integration_set_timestamp_impl(struct nabto_device_context* device, struct np_timestamp* obj)
{
    device->pl.timestamp = *obj;
}

void nabto_device_integration_set_dns_impl(struct nabto_device_context* device, struct np_dns* obj)
{
    device->pl.dns = *obj;
}

void nabto_device_integration_set_event_queue_impl(struct nabto_device_context* device, struct np_event_queue* obj)
{
    device->pl.eq = *obj;
}

void nabto_device_integration_set_local_ip_impl(struct nabto_device_context* device, struct np_local_ip* obj)
{
    device->pl.localIp = *obj;
}
