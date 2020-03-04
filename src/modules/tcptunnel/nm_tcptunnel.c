#include "nm_tcptunnel.h"
#include "nm_tcptunnel_connection.h"
#include "nm_tcptunnel_coap.h"

#include <core/nc_device.h>
#include <core/nc_stream_manager.h>
#include <platform/np_logging.h>
#include <platform/np_util.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_TUNNEL

static void nm_tcptunnel_service_stream_listener_callback(np_error_code ec, struct nc_stream_context* stream, void* data);

static void connection_event(uint64_t connectionRef, enum nc_connection_event event, void* data);
static void nm_tcptunnel_service_destroy(struct nm_tcptunnel_service* service);

np_error_code nm_tcptunnels_init(struct nm_tcptunnels* tunnels, struct nc_device_context* device)
{
    if (tunnels->device != NULL) {
        return NABTO_EC_RESOURCE_EXISTS;
    }
    np_list_init(&tunnels->services);
    tunnels->device = device;

    np_error_code ec = nm_tcptunnel_coap_init(tunnels, &device->coapServer);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    nc_device_add_connection_events_listener(device, &tunnels->connectionEventsListener, &connection_event, tunnels);

    return NABTO_EC_OK;

}

void nm_tcptunnels_deinit(struct nm_tcptunnels* tunnels)
{
    if (tunnels->device != NULL) { // if init was called
        nc_device_remove_connection_events_listener(tunnels->device, &tunnels->connectionEventsListener);

        while(!np_list_empty(&tunnels->services)) {
            struct np_list_iterator it;
            np_list_front(&tunnels->services, &it);
            struct nm_tcptunnel_service* service = np_list_get_element(&it);
            nm_tcptunnel_service_deinit(service);
            np_list_erase_iterator(&it);
        }

        nm_tcptunnel_coap_deinit(tunnels);
    }
}

void connection_event(uint64_t connectionRef, enum nc_connection_event event, void* data)
{
//    struct nm_tcptunnels* tunnels = data;
    if (event == NC_CONNECTION_EVENT_CLOSED) {
        // TODO
        /* struct np_list_iterator it; */
        /* np_list_front(tunnels) */

        /*     tunnels->tunnelsSentinel.next; */
        /* while (iterator != &tunnels->tunnelsSentinel) { */
        /*     struct nm_tcptunnel* current = iterator; */
        /*     iterator = iterator->next; */
        /*     if (current->connectionRef == connectionRef) { */
        /*         nm_tcptunnel_service_deinit(current); */
        /*         nm_tcptunnel_service_destroy(current); */
        /*     } */
        /* } */
    }
}

struct nm_tcptunnel_service* nm_tcptunnel_service_create(struct nm_tcptunnels* tunnels)
{
    struct nm_tcptunnel_service* service = calloc(1, sizeof(struct nm_tcptunnel_service));

    service->tunnels = tunnels;
    np_list_init(&service->connections);
    return service;
}

np_error_code nm_tcptunnel_service_destroy_by_id(struct nm_tcptunnels* tunnels, const char* id)
{
    struct nm_tcptunnel_service* service = nm_tcptunnels_find_service(tunnels, id);
    if (service == NULL) {
        return NABTO_EC_NOT_FOUND;
    }
    nm_tcptunnel_service_deinit(service);
    nm_tcptunnel_service_destroy(service);
    return NABTO_EC_OK;
}

void nm_tcptunnel_service_destroy(struct nm_tcptunnel_service* service)
{
    np_list_erase_item(&service->servicesListItem);
    free(service);
}

void nm_tcptunnel_service_init(struct nm_tcptunnel_service* service, const char* id, const char* type, struct np_ip_address* address, uint16_t port)
{
    service->id = strdup(id);
    service->type = strdup(type);
    service->address = *address;
    service->port = port;
}

void nm_tcptunnel_service_deinit(struct nm_tcptunnel_service* service)
{
    while(!np_list_empty(&service->connections)) {
        struct np_list_iterator it;
        np_list_front(&service->connections, &it);
        struct nm_tcptunnel_connection* connection = np_list_get_element(&it);
        np_list_erase_iterator(&it);

        nm_tcptunnel_connection_stop_from_manager(connection);
    }
    nc_stream_manager_remove_listener(&service->streamListener);
}

np_error_code nm_tcptunnel_service_init_stream_listener(struct nm_tcptunnel_service* service)
{
    struct nc_device_context* device = service->tunnels->device;
    struct nc_stream_manager_context* streamManager = &device->streamManager;
    np_error_code ec;
    ec = nc_stream_manager_add_listener(streamManager, &service->streamListener, service->streamPort, &nm_tcptunnel_service_stream_listener_callback, service);
    if (!ec) {
        service->streamPort = service->streamListener.type;
    }
    NABTO_LOG_TRACE(LOG, "Begin listening for streams on port %" PRIu32, service->streamListener.type);
    return ec;
}

void nm_tcptunnel_service_stream_listener_callback(np_error_code ec, struct nc_stream_context* stream, void* data)
{
    if (ec) {
        // probably stopped
        return;
    } else {
        struct nm_tcptunnel_service* service = data;
        struct nm_tcptunnel_connection* c = nm_tcptunnel_connection_new();
        np_error_code ec = nm_tcptunnel_connection_init(service, c, stream);
        if(!ec) {
            nm_tcptunnel_connection_start(c);
        } else {
            nm_tcptunnel_connection_free(c);
        }
    }
}

struct nm_tcptunnel_service* nm_tcptunnels_find_service(struct nm_tcptunnels* tunnels, const char* id)
{
    if (id == NULL) {
        return NULL;
    }

    struct np_list_iterator it;
    for (np_list_front(&tunnels->services, &it); !np_list_end(&it); np_list_next(&it))
    {
        struct nm_tcptunnel_service* service = np_list_get_element(&it);
        if (strcmp(service->id, id) == 0) {
            return service;
        }
    }
    return NULL;
}
