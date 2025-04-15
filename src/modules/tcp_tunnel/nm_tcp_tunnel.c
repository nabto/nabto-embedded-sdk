#include "nm_tcp_tunnel.h"
#include "nm_tcp_tunnel_connection.h"
#include "nm_tcp_tunnel_coap.h"

#include <core/nc_device.h>
#include <core/nc_stream_manager.h>
#include <platform/np_logging.h>
#include <platform/np_util.h>
#include <platform/np_allocator.h>

#include <nn/llist.h>
#include <nn/string.h>
#include <limits.h>



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
    nn_llist_init(&tunnels->services);
    nn_string_int_map_init(&tunnels->limitsByType, np_allocator_get());
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
        while(!nn_llist_empty(&tunnels->services)) {
            struct nn_llist_iterator it = nn_llist_begin(&tunnels->services);
            struct nm_tcp_tunnel_service* service = nn_llist_get_item(&it);
            nn_llist_erase(&it);
            nm_tcp_tunnel_service_deinit(service);
            nm_tcp_tunnel_service_destroy(service);

        }

        nm_tcp_tunnel_coap_deinit(tunnels);
    }
    nn_string_int_map_deinit(&tunnels->limitsByType);
}

struct nm_tcp_tunnel_service* nm_tcp_tunnel_service_create(struct nm_tcp_tunnels* tunnels)
{
    struct nm_tcp_tunnel_service* service = np_calloc(1, sizeof(struct nm_tcp_tunnel_service));
    if (service == NULL) {
        return service;
    }

    service->tunnels = tunnels;
    tunnels->weakPtrCounter++;
    service->weakPtr = tunnels->weakPtrCounter;
    nn_llist_init(&service->connections);
    nn_string_map_init(&service->metadata, np_allocator_get());
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

np_error_code nm_tcp_tunnel_limit_concurrent_connections_by_type(struct nm_tcp_tunnels* tunnels, const char* type, size_t limit)
{
    nn_string_int_map_erase(&tunnels->limitsByType, type);
    if (limit > INT_MAX) {
        // handle it as unlimited
        return NABTO_EC_OK;
    }
    struct nn_string_int_map_iterator it = nn_string_int_map_insert(&tunnels->limitsByType, type, (int)limit);
    if (nn_string_int_map_is_end(&it)) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    return NABTO_EC_OK;
}


void nm_tcp_tunnel_service_destroy(struct nm_tcp_tunnel_service* service)
{
    nn_llist_erase_node(&service->servicesListItem);
    np_free(service->id);
    np_free(service->type);
    np_free(service);
}

np_error_code nm_tcp_tunnel_service_init(struct nm_tcp_tunnel_service* service, const char* id, const char* type, struct np_ip_address* address, uint16_t port)
{
    struct nm_tcp_tunnels* tunnels = service->tunnels;
    service->id = nn_strdup(id, np_allocator_get());
    service->type = nn_strdup(type, np_allocator_get());
    service->address = *address;
    service->port = port;

    if (service->id == NULL || service->type == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    np_error_code ec = nm_tcp_tunnel_service_init_stream_listener(service);
    if (ec == NABTO_EC_OK) {
        nn_llist_append(&tunnels->services, &service->servicesListItem, service);
    }
    return ec;
}

void nm_tcp_tunnel_service_deinit(struct nm_tcp_tunnel_service* service)
{
    while(!nn_llist_empty(&service->connections)) {
        struct nn_llist_iterator it = nn_llist_begin(&service->connections);
        struct nm_tcp_tunnel_connection* connection = nn_llist_get_item(&it);
        nn_llist_erase(&it);

        nm_tcp_tunnel_connection_stop_from_manager(connection);
    }
    nn_string_map_deinit(&service->metadata);
    nc_stream_manager_remove_listener(&service->streamListener);
}

np_error_code nm_tcp_tunnel_service_init_stream_listener(struct nm_tcp_tunnel_service* service)
{
    struct nc_device_context* device = service->tunnels->device;
    struct nc_stream_manager_context* streamManager = &device->streamManager;
    np_error_code ec = nc_stream_manager_add_listener(streamManager, &service->streamListener, service->streamPort, &nm_tcp_tunnel_service_stream_listener_callback, service);
    if (!ec) {
        service->streamPort = service->streamListener.type;
    }
    NABTO_LOG_TRACE(LOG, "Begin listening for streams on port %" NABTO_LOG_PRIu32, service->streamListener.type);
    return ec;
}

void nm_tcp_tunnel_service_stream_listener_callback(np_error_code ec, struct nc_stream_context* stream, void* servicePtr)
{
    if (ec) {
        // probably stopped
        return;
    }
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
    nc_stream_destroy(stream);
}

void service_stream_iam_callback(bool allow, void* tunnelsData, void* serviceWeakPtr, void* streamData)
{
    struct nm_tcp_tunnels* tunnels = tunnelsData;
    struct nc_stream_context* stream = streamData;
    struct nm_tcp_tunnel_service* service = nm_tcp_tunnels_find_service_by_weak_ptr(tunnels, serviceWeakPtr);
    if (service == NULL) {
        // service has been removed during the authorization request
        nc_stream_destroy(stream);
        return;
    }

    if (!allow) {
        nc_stream_destroy(stream);
        return;
    }


    struct nn_string_int_map_iterator limit = nn_string_int_map_get(&tunnels->limitsByType, service->type);
    if (!nn_string_int_map_is_end(&limit)) {
        int connectionsLimit = nn_string_int_map_value(&limit);
        size_t connectionsByType = nm_tcp_tunnel_connections_by_type(tunnels, service->type);
        if ((int)connectionsByType >= connectionsLimit) {
            // too many connections
            nc_stream_destroy(stream);
            return;
        }
    }

    struct nm_tcp_tunnel_connection* c = nm_tcp_tunnel_connection_new();

    if (c == NULL) {
        nc_stream_destroy(stream);
        return;
    }

    np_error_code ec = nm_tcp_tunnel_connection_init(service, c, stream);
    if(!ec) {
        nm_tcp_tunnel_connection_start(c);
    } else {
        nm_tcp_tunnel_connection_free(c);
        nc_stream_destroy(stream);
    }
}

np_error_code nm_tcp_tunnel_service_add_metadata(struct nm_tcp_tunnels* tunnels, const char* serviceId, const char* key, const char *value)
{
    struct nm_tcp_tunnel_service* service = nm_tcp_tunnels_find_service(tunnels, serviceId);
    if (service == NULL)
    {
        return NABTO_EC_NOT_FOUND;
    }

    struct nn_string_map* metadata = &service->metadata;
    struct nn_string_map_iterator it = nn_string_map_get(metadata, key);
    if (!nn_string_map_is_end(&it))
    {
        nn_string_map_erase_iterator(metadata, &it);
    }

    nn_string_map_insert(metadata, key, value);
    return NABTO_EC_OK;
}

np_error_code nm_tcp_tunnel_service_remove_metadata(struct nm_tcp_tunnels* tunnels, const char* serviceId, const char* key)
{
    struct nm_tcp_tunnel_service* service = nm_tcp_tunnels_find_service(tunnels, serviceId);
    if (service == NULL)
    {
        return NABTO_EC_NOT_FOUND;
    }

    nn_string_map_erase(&service->metadata, key);
    return NABTO_EC_OK;
}

struct nm_tcp_tunnel_service* nm_tcp_tunnels_find_service(struct nm_tcp_tunnels* tunnels, const char* id)
{
    if (id == NULL) {
        return NULL;
    }

    struct nm_tcp_tunnel_service* service = NULL;
    NN_LLIST_FOREACH(service, &tunnels->services)
    {
        if (strcmp(service->id, id) == 0) {
            return service;
        }
    }
    return NULL;
}
struct nm_tcp_tunnel_service* nm_tcp_tunnels_find_service_by_weak_ptr(struct nm_tcp_tunnels* tunnels, void* weakPtr)
{
    struct nm_tcp_tunnel_service* service = NULL;
    NN_LLIST_FOREACH(service, &tunnels->services)
    {
        if (service->weakPtr == weakPtr) {
            return service;
        }
    }
    return NULL;
}

size_t nm_tcp_tunnel_connections_by_type(struct nm_tcp_tunnels* tunnels, const char* type)
{
    size_t connections = 0;
    struct nm_tcp_tunnel_service* service = NULL;
    NN_LLIST_FOREACH(service, &tunnels->services)
    {
        if (strcmp(service->type, type) == 0) {
            connections += nn_llist_size(&service->connections);
        }
    }
    return connections;
}
