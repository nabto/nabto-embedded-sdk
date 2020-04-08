#include <nabto/nabto_device.h>

#include "nabto_device_defines.h"
#include <platform/np_error_code.h>
#include <modules/tcp_tunnel/nm_tcp_tunnel.h>

#if _WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif


NabtoDeviceError NABTO_DEVICE_API
nabto_device_add_tcp_tunnel_service(NabtoDevice* device, const char* serviceId, const char* serviceType, const char* host, uint16_t port)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    struct in_addr in;
    int status = inet_pton(AF_INET, host, &in);
    if (status == 0) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }



    struct np_ip_address address;
    np_ip_address_assign_v4(&address, ntohl(in.s_addr));

    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nm_tcp_tunnel_service* service = nm_tcp_tunnel_service_create(&dev->tcpTunnels);
    nm_tcp_tunnel_service_init(service, serviceId, serviceType, &address, port);
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
