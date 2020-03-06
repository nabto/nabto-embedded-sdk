#include "nm_tcp_tunnel.h"
#include "nm_tcp_tunnel_connection.h"
#include "nm_tcp_tunnel_coap.h"

#include <core/nc_device.h>
#include <core/nc_stream_manager.h>
#include <platform/np_logging.h>
#include <platform/np_util.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_TUNNEL

static void nm_tcp_tunnel_service_stream_listener_callback(np_error_code ec, struct nc_stream_context* stream, void* data);

static void nm_tcp_tunnel_service_destroy(struct nm_tcp_tunnel_service* service);
static np_error_code nm_tcp_tunnel_service_init_stream_listener(struct nm_tcp_tunnel_service* service);
static void service_stream_iam_callback(bool allow, void* tunnelsData, void* serviceData, void* streamData);

np_error_code nm_tcp_tunnels_init(struct nm_tcp_tunnels* tunnels, struct nc_device_context* device)
{
    if (tunnels->device != NULL) {
        return NABTO_EC_RESOURCE_EXISTS;
    }
    np_list_init(&tunnels->services);
    tunnels->device = device;
    tunnels->weakPtrCounter = (void*)(1);

    np_error_code ec = nm_tcp_tunnel_coap_init(tunnels, &device->coapServer);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    return NABTO_EC_OK;

}

void nm_tcp_tunnels_deinit(struct nm_tcp_tunnels* tunnels)
{
    if (tunnels->device != NULL) { // if init was called
        while(!np_list_empty(&tunnels->services)) {
            struct np_list_iterator it;
            np_list_front(&tunnels->services, &it);
            struct nm_tcp_tunnel_service* service = np_list_get_element(&it);
            nm_tcp_tunnel_service_deinit(service);
            np_list_erase_iterator(&it);
        }

        nm_tcp_tunnel_coap_deinit(tunnels);
    }
}

struct nm_tcp_tunnel_service* nm_tcp_tunnel_service_create(struct nm_tcp_tunnels* tunnels)
{
    struct nm_tcp_tunnel_service* service = calloc(1, sizeof(struct nm_tcp_tunnel_service));

    service->tunnels = tunnels;
    tunnels->weakPtrCounter++;
    service->weakPtr = tunnels->weakPtrCounter;
    np_list_init(&service->connections);
    return service;
}

np_error_code nm_tcp_tunnel_service_destroy_by_id(struct nm_tcp_tunnels* tunnels, const char* id)
{
    struct nm_tcp_tunnel_service* service = nm_tcp_tunnels_find_service(tunnels, id);
    if (service == NULL) {
        return NABTO_EC_NOT_FOUND;
    }
    nm_tcp_tunnel_service_deinit(service);
    nm_tcp_tunnel_service_destroy(service);
    return NABTO_EC_OK;
}

void nm_tcp_tunnel_service_destroy(struct nm_tcp_tunnel_service* service)
{
    np_list_erase_item(&service->servicesListItem);
    free(service->id);
    free(service->type);
    free(service);
}

np_error_code nm_tcp_tunnel_service_init(struct nm_tcp_tunnel_service* service, const char* id, const char* type, struct np_ip_address* address, uint16_t port)
{
    struct nm_tcp_tunnels* tunnels = service->tunnels;
    service->id = strdup(id);
    service->type = strdup(type);
    service->address = *address;
    service->port = port;

    np_error_code ec = nm_tcp_tunnel_service_init_stream_listener(service);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    np_list_append(&tunnels->services, &service->servicesListItem, service);
    return ec;
}

void nm_tcp_tunnel_service_deinit(struct nm_tcp_tunnel_service* service)
{
    while(!np_list_empty(&service->connections)) {
        struct np_list_iterator it;
        np_list_front(&service->connections, &it);
        struct nm_tcp_tunnel_connection* connection = np_list_get_element(&it);
        np_list_erase_iterator(&it);

        nm_tcp_tunnel_connection_stop_from_manager(connection);
    }
    nc_stream_manager_remove_listener(&service->streamListener);
}

np_error_code nm_tcp_tunnel_service_init_stream_listener(struct nm_tcp_tunnel_service* service)
{
    struct nc_device_context* device = service->tunnels->device;
    struct nc_stream_manager_context* streamManager = &device->streamManager;
    np_error_code ec;
    ec = nc_stream_manager_add_listener(streamManager, &service->streamListener, service->streamPort, &nm_tcp_tunnel_service_stream_listener_callback, service);
    if (!ec) {
        service->streamPort = service->streamListener.type;
    }
    NABTO_LOG_TRACE(LOG, "Begin listening for streams on port %" PRIu32, service->streamListener.type);
    return ec;
}

void nm_tcp_tunnel_service_stream_listener_callback(np_error_code ec, struct nc_stream_context* stream, void* servicePtr)
{
    if (ec) {
        // probably stopped
        return;
    } else {
        // Service is guaranteed to be valid since removal of a service removes the listener.
        struct nm_tcp_tunnel_service* service = servicePtr;

        // we are not guaranteed that the service is not removed
        // during the authorization request, so use a weakPtr instead.
        void* serviceWeakPtr = service->weakPtr;


        struct np_platform* pl = service->tunnels->device->pl;
        struct np_authorization_request* authReq = pl->authorization.create_request(pl, stream->connectionRef, "TcpTunnel:Connect");
        if (authReq &&
            pl->authorization.add_string_attribute(authReq, "TcpTunnel:ServiceId", service->id) == NABTO_EC_OK &&
            pl->authorization.add_string_attribute(authReq, "TcpTunnel:ServiceType", service->type) == NABTO_EC_OK)
        {
            pl->authorization.check_access(authReq, service_stream_iam_callback, service->tunnels, serviceWeakPtr, stream);
            return;
        }

        pl->authorization.discard_request(authReq);
        nc_stream_release(stream);
    }
}

void service_stream_iam_callback(bool allow, void* tunnelsData, void* serviceWeakPtr, void* streamData)
{
    struct nm_tcp_tunnels* tunnels = tunnelsData;
    struct nc_stream_context* stream = streamData;
    struct nm_tcp_tunnel_service* service = nm_tcp_tunnels_find_service_by_weak_ptr(tunnels, serviceWeakPtr);
    if (service == NULL) {
        // service has been removed during the authorization request
        nc_stream_release(stream);
        return;
    }

    if (!allow) {
        nc_stream_release(stream);
        return;
    }

    struct nm_tcp_tunnel_connection* c = nm_tcp_tunnel_connection_new();

    if (c == NULL) {
        nc_stream_release(stream);
        return;
    }

    np_error_code ec = nm_tcp_tunnel_connection_init(service, c, stream);
    if(!ec) {
        nm_tcp_tunnel_connection_start(c);
    } else {
        nm_tcp_tunnel_connection_free(c);
    }
}

struct nm_tcp_tunnel_service* nm_tcp_tunnels_find_service(struct nm_tcp_tunnels* tunnels, const char* id)
{
    if (id == NULL) {
        return NULL;
    }

    struct np_list_iterator it;
    for (np_list_front(&tunnels->services, &it); !np_list_end(&it); np_list_next(&it))
    {
        struct nm_tcp_tunnel_service* service = np_list_get_element(&it);
        if (strcmp(service->id, id) == 0) {
            return service;
        }
    }
    return NULL;
}
struct nm_tcp_tunnel_service* nm_tcp_tunnels_find_service_by_weak_ptr(struct nm_tcp_tunnels* tunnels, void* weakPtr)
{
    struct np_list_iterator it;
    for (np_list_front(&tunnels->services, &it); !np_list_end(&it); np_list_next(&it))
    {
        struct nm_tcp_tunnel_service* service = np_list_get_element(&it);
        if (service->weakPtr == weakPtr) {
            return service;
        }
    }
    return NULL;
}
