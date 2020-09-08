#include "nc_device.h"
#include <platform/np_logging.h>
#include <platform/np_mdns_wrapper.h>
#include <nn/llist.h>

#define LOG NABTO_LOG_MODULE_CORE

void nc_device_attached_cb(const np_error_code ec, void* data);
uint32_t nc_device_get_reattach_time(struct nc_device_context* ctx);
static void nc_device_udp_bound_cb(const np_error_code ec, void* data);
static void nc_device_secondary_udp_bound_cb(const np_error_code ec, void* data);

np_error_code nc_device_init(struct nc_device_context* device, struct np_platform* pl)
{
    memset(device, 0, sizeof(struct nc_device_context));
    device->pl = pl;
    device->state = NC_DEVICE_STATE_SETUP;

    device->localPort = 5592;
    device->p2pPort = 5593;

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

    ec = pl->dtlsS.create(pl, &device->dtlsServer);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }

    ec = nc_coap_server_init(pl, &device->coapServer);
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


    ec = nc_stun_init(&device->stun, pl);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }

    ec = nc_stun_coap_init(&device->stunCoap, pl, &device->coapServer, &device->stun);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }

    nc_spake2_init(&device->spake2);

    ec = nc_spake2_coap_init(&device->spake2, &device->coapServer);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }


    nc_client_connection_dispatch_init(&device->clientConnect, pl, device);
    nc_stream_manager_init(&device->streamManager, pl);

    nn_llist_init(&device->eventsListeners);
    nn_llist_init(&device->deviceEvents);

    nn_string_set_init(&device->mdnsSubtypes);
    nn_string_map_init(&device->mdnsTxtItems);


    device->serverPort = 443;

    ec = np_completion_event_init(&pl->eq, &device->socketBoundCompletionEvent, &nc_device_udp_bound_cb, device);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    return NABTO_EC_OK;
}

// nc_device_deinit must NEVER be called without successfull init
void nc_device_deinit(struct nc_device_context* device) {

    struct np_platform* pl = device->pl;


    nc_spake2_coap_deinit(&device->spake2);
    nc_spake2_deinit(&device->spake2);


    nc_stream_manager_deinit(&device->streamManager);
    nc_client_connection_dispatch_deinit(&device->clientConnect);
    nc_stun_coap_deinit(&device->stunCoap);
    nc_stun_deinit(&device->stun);
    nc_rendezvous_coap_deinit(&device->rendezvousCoap);
    nc_rendezvous_deinit(&device->rendezvous);
    nc_attacher_deinit(&device->attacher);
    nc_coap_client_deinit(&device->coapClient);
    nc_coap_server_deinit(&device->coapServer);
    if (device->dtlsServer != NULL) { // was created
        pl->dtlsS.destroy(device->dtlsServer);
    }

    nn_string_set_deinit(&device->mdnsSubtypes);
    nn_string_map_deinit(&device->mdnsTxtItems);
    free(device->mdnsInstanceName);

    nc_udp_dispatch_deinit(&device->udp);
    nc_udp_dispatch_deinit(&device->localUdp);
    nc_udp_dispatch_deinit(&device->secondaryUdp);
    np_completion_event_deinit(&device->socketBoundCompletionEvent);
}

void nc_device_set_keys(struct nc_device_context* device, const unsigned char* publicKeyL, size_t publicKeySize, const unsigned char* privateKeyL, size_t privateKeySize)
{
    struct np_platform* pl = device->pl;
    nc_attacher_set_keys(&device->attacher, publicKeyL, publicKeySize, privateKeyL, privateKeySize);
    pl->dtlsS.set_keys(device->dtlsServer, publicKeyL, publicKeySize, privateKeyL, privateKeySize);
}

void nc_device_secondary_udp_bound_cb(const np_error_code ec, void* data) {
    struct nc_device_context* dev = (struct nc_device_context*)data;
    if (dev->state == NC_DEVICE_STATE_STOPPED) {
        // abort
        return;
    }
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "nc_device failed to create secondary UDP socket. Device continues without STUN");
        return;
    }
    nc_stun_set_sockets(&dev->stun, &dev->udp, &dev->secondaryUdp);

    nc_udp_dispatch_set_stun_context(&dev->udp, &dev->stun);
    nc_udp_dispatch_set_stun_context(&dev->secondaryUdp, &dev->stun);

    nc_udp_dispatch_start_recv(&dev->secondaryUdp);

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

    device->mdnsInstanceName = strdup(uniqueId);
    if (device->mdnsInstanceName == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    return NABTO_EC_OK;
}

void nc_device_local_udp_bound_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    struct np_platform* pl = dev->pl;
    if (dev->state == NC_DEVICE_STATE_STOPPED) {
        // abort
        NABTO_LOG_TRACE(LOG, "Device state STOPPED while binding local socket");
        return;
    }
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "nc_device failed to bind local UDP socket. Device continues without local connections and mDNS. Error: %s", np_error_code_to_string(ec));
        //dev->state = NC_DEVICE_STATE_STOPPED;
        return;
    } else if (dev->enableMdns) {
        uint16_t localPort = nc_udp_dispatch_get_local_port(&dev->localUdp);
        NABTO_LOG_TRACE(LOG, "Local socket bound, starting mdns on %d", localPort);
        np_mdns_publish_service(&pl->mdns, localPort, dev->mdnsInstanceName, &dev->mdnsSubtypes, &dev->mdnsTxtItems);
    } else {
        NABTO_LOG_TRACE(LOG, "Local socket bound, no mDNS");
    }
    nc_udp_dispatch_set_client_connection_context(&dev->localUdp, &dev->clientConnect);
    nc_udp_dispatch_set_rendezvous_context(&dev->localUdp, &dev->rendezvous);
    nc_udp_dispatch_start_recv(&dev->localUdp);

    np_completion_event_reinit(&dev->socketBoundCompletionEvent, &nc_device_secondary_udp_bound_cb, dev);
    nc_udp_dispatch_async_bind(&dev->secondaryUdp, dev->pl, 0, &dev->socketBoundCompletionEvent);
}

void nc_device_udp_bound_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    if (dev->state == NC_DEVICE_STATE_STOPPED) {
        // nothing is running just abort
        return;
    }
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "nc_device failed to bind primary UDP socket, Nabto device not started!");
        dev->state = NC_DEVICE_STATE_STOPPED;
        return;
    }
    nc_udp_dispatch_set_client_connection_context(&dev->udp, &dev->clientConnect);
    nc_udp_dispatch_set_rendezvous_context(&dev->udp, &dev->rendezvous);
    nc_rendezvous_set_udp_dispatch(&dev->rendezvous, &dev->udp);

    nc_attacher_start(&dev->attacher, dev->hostname, dev->serverPort, &dev->udp);

    nc_udp_dispatch_start_recv(&dev->udp);

    np_completion_event_reinit(&dev->socketBoundCompletionEvent, &nc_device_local_udp_bound_cb, dev);
    nc_udp_dispatch_async_bind(&dev->localUdp, dev->pl, dev->localPort, &dev->socketBoundCompletionEvent);
}


np_error_code nc_device_start(struct nc_device_context* dev,
                              const char* appName, const char* appVersion,
                              const char* productId, const char* deviceId,
                              const char* hostname)
{
    struct np_platform* pl = dev->pl;
    NABTO_LOG_INFO(LOG, "Starting Nabto Device");
    dev->state = NC_DEVICE_STATE_RUNNING;
    dev->productId = productId;
    dev->deviceId = deviceId;
    dev->hostname = hostname;
    dev->connectionRef = 0;

    np_error_code ec;
    ec = nc_device_populate_mdns(dev);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    nc_attacher_set_app_info(&dev->attacher, appName, appVersion);
    nc_attacher_set_device_info(&dev->attacher, productId, deviceId);

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
    nc_udp_dispatch_abort(&dev->secondaryUdp);
    nc_rendezvous_remove_udp_dispatch(&dev->rendezvous);
    nc_stun_remove_sockets(&dev->stun);
    nc_attacher_stop(&dev->attacher);
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
    return nc_client_connection_dispatch_connection_from_ref(&dev->clientConnect, ref);
}

void nc_device_add_connection_events_listener(struct nc_device_context* dev, struct nc_connection_events_listener* listener, nc_connection_event_callback cb, void* userData)
{
    listener->cb = cb;
    listener->userData = userData;

    nn_llist_append(&dev->eventsListeners, &listener->eventListenersNode, listener);
}

void nc_device_remove_connection_events_listener(struct nc_device_context* dev, struct nc_connection_events_listener* listener)
{
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
    nn_llist_erase_node(&listener->eventsListenersNode);
}

void nc_device_events_listener_notify(enum nc_device_event event, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;

    if (event == NC_DEVICE_EVENT_ATTACHED && dev->attacher.stunPort != 0) {
        dev->stunHost = dev->attacher.stunHost;
        dev->stunPort = dev->attacher.stunPort;
        nc_stun_set_host(&dev->stun, dev->stunHost, dev->stunPort);
    }

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
