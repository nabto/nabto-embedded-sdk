#include "nabto_device_platform_adapter.h"

#include "nabto_device_defines.h"

// Get the
void* nabto_device_platform_adapter_get(struct nabto_device_context* device)
{
    return device->platformAdapter;
}

void nabto_device_platform_adapter_set(struct nabto_device_context* device, void* adapter)
{
    device->platformAdapter = adapter;
}

void nabto_device_platform_adapter_set_udp(struct nabto_device_context* device, struct np_udp* obj)
{
    device->pl.udp = *(obj->vptr);
    device->pl.udpImpl = obj->data;
}

void nabto_device_platform_adapter_set_tcp(struct nabto_device_context* device, struct np_tcp* obj)
{
    device->pl.tcp = *(obj->vptr);
    device->pl.tcpData = obj->data;
}

void nabto_device_platform_adapter_set_timestamp(struct nabto_device_context* device, struct np_timestamp* obj)
{
    device->pl.ts = *(obj->vptr);
    device->pl.tsImpl = obj->data;
}

void nabto_device_platform_adapter_set_dns(struct nabto_device_context* device, struct np_dns* obj)
{
    device->pl.dns = *(obj->vptr);
    device->pl.dnsData = obj->data;
}

void nabto_device_platform_adapter_set_event_queue(struct nabto_device_context* device, struct np_event_queue* obj)
{
    device->pl.eq = *(obj->vptr);
    device->pl.eqData = obj->data;
}

void nabto_device_platform_adapter_set_local_ip(struct nabto_device_context* device, struct np_local_ip* obj)
{
    device->pl.localIp = *(obj->vptr);
    device->pl.localIpData = obj->data;
}
