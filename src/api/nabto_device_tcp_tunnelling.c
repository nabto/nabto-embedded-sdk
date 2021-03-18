#include <nabto/nabto_device.h>

#include "nabto_device_defines.h"
#include <api/nabto_device_error.h>
#include <platform/np_error_code.h>
#include <modules/tcp_tunnel/nm_tcp_tunnel.h>

NabtoDeviceError NABTO_DEVICE_API
nabto_device_add_tcp_tunnel_service(NabtoDevice* device, const char* serviceId, const char* serviceType, const char* host, uint16_t port)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    struct np_ip_address address;
    if (!np_ip_address_read_v4(host, &address)) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }

    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nm_tcp_tunnel_service* service = nm_tcp_tunnel_service_create(&dev->tcpTunnels);
    if (service == NULL) {
        ec = NABTO_EC_OUT_OF_MEMORY;
    } else {
        ec = nm_tcp_tunnel_service_init(service, serviceId, serviceType, &address, port);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_remove_tcp_tunnel_service(NabtoDevice* device, const char* serviceId)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nm_tcp_tunnel_service_destroy_by_id(&dev->tcpTunnels, serviceId);
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return nabto_device_error_core_to_api(ec);
}


NabtoDeviceError NABTO_DEVICE_API
nabto_device_tcp_tunnel_service_limit_concurrent_connections(NabtoDevice* device, const char* serviceId, int limit)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nm_tcp_tunnel_limit_concurrent_connections_by_id(&dev->tcpTunnels, serviceId, limit);
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return nabto_device_error_core_to_api(ec);
}
