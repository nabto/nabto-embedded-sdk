#include <nabto/nabto_device_config.h>
#include "nc_device.h"
#include "nc_config.h"
#include <platform/np_logging.h>
#include <platform/np_mdns_wrapper.h>
#include <platform/np_allocator.h>
#include <nn/llist.h>
#include <nn/string.h>

#define LOG NABTO_LOG_MODULE_CORE

void nc_device_attached_cb(const np_error_code ec, void* data);
uint32_t nc_device_get_reattach_time(struct nc_device_context* ctx);
static void nc_device_p2p_socket_bound_cb(const np_error_code ec, void* data);
static void nc_device_local_socket_bound_cb(const np_error_code ec, void* data);
static void nc_device_secondary_stun_socket_bound_cb(const np_error_code ec, void* data);
static void nc_device_sockets_bound(struct nc_device_context* dev);
static void nc_device_resolve_start_close_callbacks(struct nc_device_context* dev, np_error_code ec);
// return true iff the mdns capabilities are available.
static bool nc_device_has_mdns_capability(struct nc_device_context* ctx);


// log function for nn_log
static void module_logger(void* userData, enum nn_log_severity severity, const char* module, const char* file, int line, const char* fmt, va_list args);

np_error_code nc_device_init(struct nc_device_context* device, struct np_platform* pl)
{
    memset(device, 0, sizeof(struct nc_device_context));
    device->pl = pl;
    device->state = NC_DEVICE_STATE_SETUP;

    device->localPort = 5592;
    device->p2pPort = 5593;
    device->serverPort = 443;


    device->appName = NULL;
    device->appVersion = NULL;
    device->productId = NULL;
    device->deviceId = NULL;
    device->hostname = NULL;
    device->connectionRef = 0;
    device->enableAttach = true;

    nn_log_init(&device->moduleLogger, module_logger, device);

    nn_llist_init(&device->eventsListeners);
    nn_llist_init(&device->deviceEvents);

    nn_string_set_init(&device->mdnsSubtypes, np_allocator_get());
    nn_string_map_init(&device->mdnsTxtItems, np_allocator_get());

    device->initialized = true; // This will be set to false again if we cleanup after a failed init.


    np_error_code ec;
    ec = nc_udp_dispatch_init(&device->udp, pl);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }
    ec = nc_udp_dispatch_init(&device->secondaryUdp, pl);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }
    ec = nc_udp_dispatch_init(&device->localUdp, pl);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
    ec = pl->dtlsS.create(pl, &device->dtlsServer);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }
#endif
    ec = nc_coap_server_init(pl, &device->moduleLogger, &device->coapServer);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }

    ec = nc_coap_client_init(pl, &device->coapClient);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }

    ec = nc_attacher_init(&device->attacher, pl, device, &device->coapClient, &nc_device_events_listener_notify, device);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }

    ec = nc_rendezvous_init(&device->rendezvous, pl);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }
    ec = nc_rendezvous_coap_init(&device->rendezvousCoap, &device->coapServer, &device->rendezvous);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }


    ec = nc_stun_init(&device->stun, device, pl);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }

    ec = nc_stun_coap_init(&device->stunCoap, pl, &device->coapServer, &device->stun);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }

#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    nc_spake2_init(&device->spake2, pl);

    ec = nc_spake2_coap_init(&device->spake2, &device->coapServer);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }
#endif
    ec = nc_connections_init(&device->connections);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "nc_device failed init connections. %s", np_error_code_to_string(ec));
        nc_device_deinit(device);
        return ec;
    }

    ec = nc_client_connection_dispatch_init(&device->clientConnect, pl, device);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "nc_device failed init client connection dispatch. %s", np_error_code_to_string(ec));
        nc_device_deinit(device);
        return ec;
    }

    nc_stream_manager_init(&device->streamManager, pl, &device->moduleLogger);


    ec = np_completion_event_init(&pl->eq, &device->socketBoundCompletionEvent, NULL, NULL);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }

    device->initialized = true;

    return NABTO_EC_OK;
}

void nc_device_deinit(struct nc_device_context* device) {
    if (!device->initialized) {
        return;
    }

    struct np_platform* pl = device->pl;

    if (device->mdnsPublished) {
        np_mdns_unpublish_service(&pl->mdns);
    }

#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    nc_spake2_coap_deinit(&device->spake2);
    nc_spake2_deinit(&device->spake2);
#endif


    nc_stream_manager_deinit(&device->streamManager);
    nc_client_connection_dispatch_deinit(&device->clientConnect);
    nc_connections_deinit(&device->connections);
    nc_stun_coap_deinit(&device->stunCoap);
    nc_stun_deinit(&device->stun);
    nc_rendezvous_coap_deinit(&device->rendezvousCoap);
    nc_rendezvous_deinit(&device->rendezvous);
    nc_attacher_deinit(&device->attacher);
    nc_coap_client_deinit(&device->coapClient);
    nc_coap_server_deinit(&device->coapServer);

#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
    if (device->dtlsServer != NULL) { // was created
        pl->dtlsS.destroy(device->dtlsServer);
    }
#endif

    nn_string_set_deinit(&device->mdnsSubtypes);
    nn_string_map_deinit(&device->mdnsTxtItems);
    np_free(device->mdnsInstanceName);

    nc_udp_dispatch_deinit(&device->udp);
    nc_udp_dispatch_deinit(&device->localUdp);
    nc_udp_dispatch_deinit(&device->secondaryUdp);
    np_completion_event_deinit(&device->socketBoundCompletionEvent);

    np_free(device->productId);
    np_free(device->deviceId);
    np_free(device->appName);
    np_free(device->appVersion);
    np_free(device->hostname);

    device->initialized = false;
}

void nc_device_resolve_start_close_callbacks(struct nc_device_context* dev, np_error_code ec)
{
    nc_device_close_callback closeCb = dev->closeCb;
    dev->closeCb = NULL;
    void* closeCbData = dev->closeCbData;

    nc_device_close_callback startCb = dev->startCb;
    dev->startCb = NULL;
    void* startCbData = dev->startCbData;

    if (closeCb != NULL) {
        closeCb(ec, closeCbData);
    }

    if (startCb != NULL) {
        startCb(ec, startCbData);
    }

}

np_error_code nc_device_set_keys(struct nc_device_context* device, const unsigned char* publicKeyL, size_t publicKeySize, const unsigned char* privateKeyL, size_t privateKeySize, const uint8_t* fingerprint)
{
    memcpy(device->fingerprint, fingerprint, 32);
    np_error_code ec = nc_attacher_set_keys(&device->attacher, publicKeyL, publicKeySize, privateKeyL, privateKeySize);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
    ec = device->pl->dtlsS.set_keys(device->dtlsServer, publicKeyL, publicKeySize, privateKeyL, privateKeySize);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
#endif
    return NABTO_EC_OK;
}

void nc_device_secondary_stun_socket_bound_cb(const np_error_code ec, void* data) {
    struct nc_device_context* dev = (struct nc_device_context*)data;
    if (dev->state == NC_DEVICE_STATE_STOPPED) {
        nc_device_resolve_start_close_callbacks(dev, NABTO_EC_STOPPED);
        return;
    }
    if (ec != NABTO_EC_OK) {
        dev->state = NC_DEVICE_STATE_STOPPED;
        NABTO_LOG_ERROR(LOG, "nc_device failed to create secondary stun UDP socket. %s", np_error_code_to_string(ec));
        nc_device_resolve_start_close_callbacks(dev, ec);
        return;
    }
    nc_device_sockets_bound(dev);
}

void nc_device_local_socket_bound_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    struct np_platform* pl = dev->pl;
    if (dev->state == NC_DEVICE_STATE_STOPPED) {
        nc_device_resolve_start_close_callbacks(dev, NABTO_EC_STOPPED);
        NABTO_LOG_TRACE(LOG, "Device state STOPPED while binding local socket");
        return;
    }
    if (ec != NABTO_EC_OK) {
        dev->state = NC_DEVICE_STATE_STOPPED;
        if (ec == NABTO_EC_ADDRESS_IN_USE) {
            NABTO_LOG_ERROR(LOG, "The local socket could not be bound to the port %d", dev->localPort);
        } else {
            NABTO_LOG_ERROR(LOG, "nc_device failed to bind local UDP socket. Error: %s", np_error_code_to_string(ec));
        }
        nc_device_resolve_start_close_callbacks(dev, ec);
        return;
    }

    np_completion_event_reinit(&dev->socketBoundCompletionEvent, &nc_device_secondary_stun_socket_bound_cb, dev);
    nc_udp_dispatch_async_bind(&dev->secondaryUdp, pl, 0, &dev->socketBoundCompletionEvent);
}

void nc_device_p2p_socket_bound_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    if (dev->state == NC_DEVICE_STATE_STOPPED) {
        nc_device_resolve_start_close_callbacks(dev, NABTO_EC_STOPPED);
        return;
    }
    if (ec != NABTO_EC_OK) {
        if (ec == NABTO_EC_ADDRESS_IN_USE) {
            NABTO_LOG_ERROR(LOG, "The p2p socket could not be bound to the port %d", dev->p2pPort);
        } else {
            NABTO_LOG_ERROR(LOG, "nc_device failed to bind primary UDP socket, error: %s - Nabto device not started!", np_error_code_to_string(ec));
        }
        dev->state = NC_DEVICE_STATE_STOPPED;
        nc_device_resolve_start_close_callbacks(dev, ec);
        return;
    }
    np_completion_event_reinit(&dev->socketBoundCompletionEvent, &nc_device_local_socket_bound_cb, dev);
    nc_udp_dispatch_async_bind(&dev->localUdp, dev->pl, dev->localPort, &dev->socketBoundCompletionEvent);
}


static np_error_code nc_device_populate_mdns(struct nc_device_context* device)
{
    // add txt records to mdns
    struct nn_string_map_iterator it;
    it = nn_string_map_insert(&device->mdnsTxtItems, "productid", device->productId);
    if (nn_string_map_is_end(&it)) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    it = nn_string_map_insert(&device->mdnsTxtItems, "deviceid", device->deviceId);
    if (nn_string_map_is_end(&it)) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    char uniqueId[64];
    if (strlen(device->productId) + 1 + strlen(device->deviceId) > 63) {
        return NABTO_EC_INVALID_STATE;
    }

    char* ptr = uniqueId;
    strcpy(ptr, device->productId);
    ptr += strlen(device->productId);
    strcpy(ptr, "-");
    ptr += strlen("-");
    strcpy(ptr, device->deviceId);
    if (!nn_string_set_insert(&device->mdnsSubtypes, uniqueId)) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    device->mdnsInstanceName = nn_strdup(uniqueId, np_allocator_get());
    if (device->mdnsInstanceName == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    return NABTO_EC_OK;
}

void nc_device_sockets_bound(struct nc_device_context* dev)
{
    // start receive on p2p socket
    nc_udp_dispatch_set_client_connection_context(&dev->udp, &dev->clientConnect);
    nc_udp_dispatch_set_rendezvous_context(&dev->udp, &dev->rendezvous);
    nc_rendezvous_set_udp_dispatch(&dev->rendezvous, &dev->udp);

    if (dev->enableAttach) {
        np_error_code ec = nc_attacher_start(&dev->attacher, dev->hostname, dev->serverPort, &dev->udp);
        if (ec != NABTO_EC_OK) {
            nc_device_resolve_start_close_callbacks(dev, ec);
            return;
        }
    }

    nc_udp_dispatch_start_recv(&dev->udp);

    // start recv on local socket
    nc_udp_dispatch_set_client_connection_context(&dev->localUdp, &dev->clientConnect);
    nc_udp_dispatch_set_rendezvous_context(&dev->localUdp, &dev->rendezvous);
    nc_udp_dispatch_start_recv(&dev->localUdp);

    struct np_platform* pl = dev->pl;
    // start mdns
    if (dev->enableMdns) {
        if (pl->mdns.mptr == NULL) {
            NABTO_LOG_ERROR(LOG, "Missing mdns module, not publishing the mdns service");
        } else {
            uint16_t localPort = nc_udp_dispatch_get_local_port(&dev->localUdp);
            NABTO_LOG_TRACE(LOG, "Local socket bound, starting mdns on %d",
                            localPort);
            np_mdns_publish_service(&pl->mdns, localPort, dev->mdnsInstanceName,
                                    &dev->mdnsSubtypes, &dev->mdnsTxtItems);
            dev->mdnsPublished = true;
        }
    }

    // start recv for the stun socket
    nc_stun_set_sockets(&dev->stun, &dev->udp, &dev->secondaryUdp);

    nc_udp_dispatch_set_stun_context(&dev->udp, &dev->stun);
    nc_udp_dispatch_set_stun_context(&dev->secondaryUdp, &dev->stun);

    nc_udp_dispatch_start_recv(&dev->secondaryUdp);

    // device has been started
    nc_device_resolve_start_close_callbacks(dev, NABTO_EC_OK);
}



np_error_code nc_device_start(struct nc_device_context* dev,
                              const char* defaultServerUrlSuffix,
                              nc_device_start_callback cb, void* userData)
{
    struct np_platform* pl = dev->pl;
    NABTO_LOG_INFO(LOG, "Starting Nabto Device");


    if (dev->deviceId == NULL || dev->productId == NULL) {
        NABTO_LOG_ERROR(LOG, "Missing deviceId or productdId");
        return NABTO_EC_INVALID_STATE;
    }

    if (dev->hostname == NULL) {
        dev->hostname = np_calloc(1, strlen(dev->productId) + strlen(defaultServerUrlSuffix)+1);
        if (dev->hostname == NULL) {
            return NABTO_EC_OUT_OF_MEMORY;
        }
        char* ptr = dev->hostname;

        strcpy(ptr, dev->productId);
        ptr = ptr + strlen(dev->productId);
        strcpy(ptr, defaultServerUrlSuffix);
    }

    np_error_code ec = NABTO_EC_OK;
    ec = nc_device_populate_mdns(dev);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    dev->state = NC_DEVICE_STATE_RUNNING;
    nc_attacher_set_app_info(&dev->attacher, dev->appName, dev->appVersion);
    nc_attacher_set_device_info(&dev->attacher, dev->productId, dev->deviceId);

    dev->startCb = cb;
    dev->startCbData = userData;

    np_completion_event_reinit(&dev->socketBoundCompletionEvent, &nc_device_p2p_socket_bound_cb, dev);
    nc_udp_dispatch_async_bind(&dev->udp, pl, dev->p2pPort, &dev->socketBoundCompletionEvent);
    return NABTO_EC_OK;
}

void nc_device_attach_closed_cb(void* data) {
    struct nc_device_context* dev = (struct nc_device_context*)data;
    nc_udp_dispatch_abort(&dev->udp);
    nc_udp_dispatch_abort(&dev->localUdp);
    nc_udp_dispatch_abort(&dev->secondaryUdp);
    if (dev->closeCb) {
        nc_device_close_callback cb = dev->closeCb;
        dev->closeCb = NULL;
        cb(NABTO_EC_OK, dev->closeCbData);
        return;
    }
}

void nc_device_client_connections_closed_cb(void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    nc_attacher_async_close(&dev->attacher, nc_device_attach_closed_cb, dev);
}

void nc_device_stop(struct nc_device_context* dev)
{
    dev->state = NC_DEVICE_STATE_STOPPED;
    nc_udp_dispatch_abort(&dev->udp);
    nc_udp_dispatch_abort(&dev->localUdp);
    nc_udp_dispatch_abort(&dev->secondaryUdp);
    nc_rendezvous_remove_udp_dispatch(&dev->rendezvous);
    nc_stun_stop(&dev->stun);
    nc_stun_remove_sockets(&dev->stun);
    nc_attacher_stop(&dev->attacher);
    nc_coap_client_stop(&dev->coapClient);
}

np_error_code nc_device_close(struct nc_device_context* dev, nc_device_close_callback cb, void* data)
{
    if (dev->state != NC_DEVICE_STATE_RUNNING) {
        return NABTO_EC_INVALID_STATE;
    }
    dev->closeCb = cb;
    dev->closeCbData = data;

    dev->state = NC_DEVICE_STATE_STOPPED;

    //nc_device_stop(dev);

    np_error_code ec = nc_client_connection_dispatch_async_close(&dev->clientConnect, &nc_device_client_connections_closed_cb, dev);
    if (ec == NABTO_EC_STOPPED) {
        nc_device_client_connections_closed_cb(dev);
    }
    return NABTO_EC_OK;
}

np_error_code nc_device_next_connection_ref(struct nc_device_context* dev, uint64_t* ref)
{
    uint64_t prev = dev->connectionRef;
    dev->connectionRef += 1;
    if (prev > dev->connectionRef ) {
        NABTO_LOG_ERROR(LOG, "Connection reference counter wrapped. This should not happen");
        return NABTO_EC_UNKNOWN;
    }
    *ref = dev->connectionRef;
    return NABTO_EC_OK;
}

uint64_t nc_device_get_connection_ref_from_stream(struct nc_device_context* dev, struct nabto_stream* stream)
{
    return nc_stream_manager_get_connection_ref(&dev->streamManager, stream);
}


struct nc_client_connection* nc_device_connection_from_ref(struct nc_device_context* dev, uint64_t ref)
{
    // TODO: change to nc_connection*
    struct nc_connection* conn = nc_connections_connection_from_ref(&dev->connections, ref);
    return conn->connectionImplCtx;
}

void nc_device_add_connection_events_listener(struct nc_device_context* dev, struct nc_connection_events_listener* listener, nc_connection_event_callback cb, void* userData)
{
    listener->cb = cb;
    listener->userData = userData;

    nn_llist_append(&dev->eventsListeners, &listener->eventListenersNode, listener);
}

void nc_device_remove_connection_events_listener(struct nc_device_context* dev, struct nc_connection_events_listener* listener)
{
    (void)dev;
    nn_llist_erase_node(&listener->eventListenersNode);
}

void nc_device_connection_events_listener_notify(struct nc_device_context* dev, uint64_t connectionRef, enum nc_connection_event event)
{
    struct nn_llist_iterator iterator = nn_llist_begin(&dev->eventsListeners);

    while(!nn_llist_is_end(&iterator))
    {
        // increment iterator now, such that it's allowed to remove
        // the listener from the connection in from the event handler.
        struct nc_connection_events_listener* listener = nn_llist_get_item(&iterator);
        nn_llist_next(&iterator);
        listener->cb(connectionRef, event, listener->userData);
    }
}

void nc_device_add_device_events_listener(struct nc_device_context* dev, struct nc_device_events_listener* listener, nc_device_event_callback cb, void* userData)
{
    listener->cb = cb;
    listener->userData = userData;

    nn_llist_append(&dev->deviceEvents, &listener->eventsListenersNode, listener);
}

void nc_device_remove_device_events_listener(struct nc_device_context* dev, struct nc_device_events_listener* listener)
{
    (void)dev;
    nn_llist_erase_node(&listener->eventsListenersNode);
}

void nc_device_events_listener_notify(enum nc_device_event event, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;

    struct nn_llist_iterator iterator = nn_llist_begin(&dev->deviceEvents);
    while (!nn_llist_is_end(&iterator))
    {
        // increment iterator now, such that it's allowed to remove
        // the listener from the connection in from the event handler.
        struct nc_device_events_listener* current = nn_llist_get_item(&iterator);
        nn_llist_next(&iterator);

        current->cb(event, current->userData);
    }
}

np_error_code nc_device_add_server_connect_token(struct nc_device_context* dev, const char* token)
{
    return nc_attacher_add_server_connect_token(&dev->attacher, token);
}

np_error_code nc_device_is_server_connect_tokens_synchronized(struct nc_device_context* dev)
{
    return nc_attacher_is_server_connect_tokens_synchronized(&dev->attacher);
}

np_error_code nc_device_set_app_name(struct nc_device_context* dev, const char* name)
{
    np_free(dev->appName);
    dev->appName = nn_strdup(name, np_allocator_get());
    if (dev->appName == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    return NABTO_EC_OK;
}

const char* nc_device_get_app_name(struct nc_device_context* dev)
{
    return dev->appName;
}

np_error_code nc_device_set_app_version(struct nc_device_context* dev, const char* version)
{
    np_free(dev->appVersion);
    dev->appVersion = nn_strdup(version, np_allocator_get());
    if (dev->appVersion == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    return NABTO_EC_OK;
}

const char* nc_device_get_app_version(struct nc_device_context* dev)
{
    return dev->appVersion;
}


np_error_code nc_device_set_product_id(struct nc_device_context* dev, const char* productId)
{
    np_free(dev->productId);
    dev->productId = nn_strdup(productId, np_allocator_get());
    if (dev->productId == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    return NABTO_EC_OK;
}

np_error_code nc_device_set_device_id(struct nc_device_context* dev, const char* deviceId)
{
    np_free(dev->deviceId);
    dev->deviceId = nn_strdup(deviceId, np_allocator_get());
    if (dev->deviceId == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    return NABTO_EC_OK;
}

np_error_code nc_device_set_server_url(struct nc_device_context* dev, const char* serverUrl)
{
    np_free(dev->hostname);
    dev->hostname = nn_strdup(serverUrl, np_allocator_get());
    if (dev->hostname == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    return NABTO_EC_OK;
}

static void reload_mdns(struct nc_device_context* dev)
{
    if (dev->mdnsPublished) {
        struct np_platform* pl = dev->pl;
        np_mdns_unpublish_service(&pl->mdns);
        uint16_t localPort = nc_udp_dispatch_get_local_port(&dev->localUdp);
        np_mdns_publish_service(&pl->mdns, localPort, dev->mdnsInstanceName, &dev->mdnsSubtypes, &dev->mdnsTxtItems);
    }
}

np_error_code nc_device_disable_remote_access(struct nc_device_context* dev)
{
    if (dev->state != NC_DEVICE_STATE_SETUP) {
        return NABTO_EC_INVALID_STATE;
    }
    dev->enableAttach = false;
    return NABTO_EC_OK;
}

void nc_device_attach_disabled_cb(void* data) {
    nc_device_events_listener_notify(NC_DEVICE_EVENT_DETACHED, data);
}

np_error_code nc_device_set_basestation_attach(struct nc_device_context* dev, bool enabled)
{
    if (dev->state == NC_DEVICE_STATE_SETUP) {
        dev->enableAttach = enabled;
        return NABTO_EC_OK;
    } else if (dev->state == NC_DEVICE_STATE_RUNNING && enabled && !dev->enableAttach) {
        dev->enableAttach = true;
        return nc_attacher_start(&dev->attacher, dev->hostname, dev->serverPort, &dev->udp);
    } else if (dev->state == NC_DEVICE_STATE_RUNNING && enabled) {
        return nc_attacher_restart(&dev->attacher);
    } else if (dev->state == NC_DEVICE_STATE_RUNNING && !enabled) {
        return nc_attacher_async_close(&dev->attacher, nc_device_attach_disabled_cb, dev);
    } else { // NC_DEVICE_STATE_CLOSED
        return NABTO_EC_INVALID_STATE;
    }
}

np_error_code nc_device_enable_mdns(struct nc_device_context* dev)
{
    if (!nc_device_has_mdns_capability(dev)) {
        return NABTO_EC_NOT_IMPLEMENTED;
    }
    if (dev->state != NC_DEVICE_STATE_SETUP) {
        return NABTO_EC_INVALID_STATE;
    }
    dev->enableMdns = true;
    return NABTO_EC_OK;
}

np_error_code nc_device_mdns_add_subtype(struct nc_device_context* dev, const char* subtype)
{
    if (!nc_device_has_mdns_capability(dev)) {
        return NABTO_EC_NOT_IMPLEMENTED;
    }
    if (!nn_string_set_insert(&dev->mdnsSubtypes, subtype)) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    reload_mdns(dev);
    return NABTO_EC_OK;
}


np_error_code nc_device_mdns_add_txt_item(struct nc_device_context* dev, const char* key, const char* value)
{
    if (!nc_device_has_mdns_capability(dev)) {
        return NABTO_EC_NOT_IMPLEMENTED;
    }
    nn_string_map_erase(&dev->mdnsTxtItems, key);
    struct nn_string_map_iterator it = nn_string_map_insert(&dev->mdnsTxtItems, key, value);
    if (nn_string_map_is_end(&it)) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    reload_mdns(dev);
    return NABTO_EC_OK;
}

void module_logger(void* userData, enum nn_log_severity severity, const char* module, const char* file, int line, const char* fmt, va_list args)
{
    (void)userData; (void)module;
     if (severity == NN_LOG_SEVERITY_INFO) {
        np_log.log(NABTO_LOG_SEVERITY_INFO, NABTO_LOG_MODULE_NONE, line, file, fmt, args);
    } else if (severity == NN_LOG_SEVERITY_TRACE) {
        np_log.log(NABTO_LOG_SEVERITY_TRACE, NABTO_LOG_MODULE_NONE, line, file, fmt, args);

    } else if (severity == NN_LOG_SEVERITY_WARN) {
        np_log.log(NABTO_LOG_SEVERITY_WARN, NABTO_LOG_MODULE_NONE, line, file, fmt, args);

    } else if (severity == NN_LOG_SEVERITY_ERROR) {
        np_log.log(NABTO_LOG_SEVERITY_ERROR, NABTO_LOG_MODULE_NONE, line, file, fmt, args);

    }
}

bool nc_device_has_mdns_capability(struct nc_device_context* ctx)
{
    return ctx->pl->mdns.mptr != NULL;
}
