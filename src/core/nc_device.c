#include "nc_device.h"
#include "nc_iam_coap.h"
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_CORE

void nc_device_attached_cb(const np_error_code ec, void* data);
uint32_t nc_device_get_reattach_time(struct nc_device_context* ctx);


np_error_code nc_device_init(struct nc_device_context* device, struct np_platform* pl)
{
    memset(device, 0, sizeof(struct nc_device_context));
    device->pl = pl;
    device->state = NC_DEVICE_STATE_SETUP;
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

    ec = pl->dtlsS.create(pl, &device->dtlsServer);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }
    nc_iam_init(&device->iam);
    ec = nc_coap_server_init(pl, &device->coapServer);
    if (ec != NABTO_EC_OK) {
        nc_device_deinit(device);
        return ec;
    }
    nc_iam_coap_register_handlers(device);
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

    nc_client_connection_dispatch_init(&device->clientConnect, pl, device);
    nc_stream_manager_init(&device->streamManager, pl);

    device->eventsListenerSentinel.next = &device->eventsListenerSentinel;
    device->eventsListenerSentinel.prev = &device->eventsListenerSentinel;

    device->deviceEventsSentinel.next = &device->deviceEventsSentinel;
    device->deviceEventsSentinel.prev = &device->deviceEventsSentinel;

    device->serverPort = 4433;

    return NABTO_EC_OK;
}

// nc_device_deinit must NEVER be called without successfull init
void nc_device_deinit(struct nc_device_context* device) {

    struct np_platform* pl = device->pl;

    np_event_queue_cancel_event(device->pl, &device->closeEvent);
    if (device->mdns) {
        pl->mdns.stop(device->mdns);
        device->mdns = NULL;
    }
    nc_stream_manager_deinit(&device->streamManager);
    nc_client_connection_dispatch_deinit(&device->clientConnect);
    nc_stun_coap_deinit(&device->stunCoap);
    nc_stun_deinit(&device->stun);
    nc_rendezvous_coap_deinit(&device->rendezvousCoap);
    nc_rendezvous_deinit(&device->rendezvous);
    nc_attacher_deinit(&device->attacher);
    nc_coap_client_deinit(&device->coapClient);
    nc_coap_server_deinit(&device->coapServer);
    nc_iam_deinit(&device->iam);
    if (device->dtlsServer != NULL) { // was created
        pl->dtlsS.destroy(device->dtlsServer);
    }
    nc_udp_dispatch_deinit(&device->udp);
    nc_udp_dispatch_deinit(&device->secondaryUdp);
}

uint16_t nc_device_mdns_get_port(void* userData)
{
    struct nc_device_context* dev = (struct nc_device_context*)userData;
    return nc_udp_dispatch_get_local_port(&dev->udp);
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
    nc_stun_init_config_and_sockets(&dev->stun, dev->stunHost, &dev->udp, &dev->secondaryUdp);

    nc_udp_dispatch_set_stun_context(&dev->udp, &dev->stun);
    nc_udp_dispatch_set_stun_context(&dev->secondaryUdp, &dev->stun);
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
    nc_rendezvous_set_udp_dispatch(&dev->rendezvous, &dev->udp);

    nc_attacher_start(&dev->attacher, dev->hostname, dev->serverPort, &dev->udp);

    if (dev->enableMdns) {
        dev->pl->mdns.start(&dev->mdns, dev->pl, dev->productId, dev->deviceId, nc_device_mdns_get_port, dev);
    }

    np_error_code ec2 = nc_udp_dispatch_async_bind(&dev->secondaryUdp, dev->pl, 0, &nc_device_secondary_udp_bound_cb, dev);
    if (ec2 != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "nc_device failed to bind secondary UDP socket");
    }
}

np_error_code nc_device_start(struct nc_device_context* dev,
                              const char* appName, const char* appVersion,
                              const char* productId, const char* deviceId,
                              const char* hostname, const char* stunHost,
                              const uint16_t port, bool enableMdns)
{
    struct np_platform* pl = dev->pl;
    NABTO_LOG_INFO(LOG, "Starting Nabto Device");
    dev->state = NC_DEVICE_STATE_RUNNING;
    dev->enableMdns = enableMdns;
    dev->stunHost = stunHost;
    dev->productId = productId;
    dev->deviceId = deviceId;
    dev->hostname = hostname;
    dev->connectionRef = 0;

    nc_attacher_set_app_info(&dev->attacher, appName, appVersion);
    nc_attacher_set_device_info(&dev->attacher, productId, deviceId);

    np_error_code ec = nc_udp_dispatch_async_bind(&dev->udp, pl, port, &nc_device_udp_bound_cb, dev);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    return NABTO_EC_OK;
}

void nc_device_attach_closed_cb(void* data) {
    struct nc_device_context* dev = (struct nc_device_context*)data;
    nc_udp_dispatch_abort(&dev->udp);
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

np_error_code nc_device_close(struct nc_device_context* dev, nc_device_close_callback cb, void* data)
{
    if (dev->state != NC_DEVICE_STATE_RUNNING) {
        return NABTO_EC_INVALID_STATE;
    }
    dev->closeCb = cb;
    dev->closeCbData = data;
    dev->state = NC_DEVICE_STATE_STOPPED;
    nc_rendezvous_remove_udp_dispatch(&dev->rendezvous);
    nc_stun_deinit_sockets(&dev->stun);
    if (dev->enableMdns && dev->mdns) {
        dev->pl->mdns.stop(dev->mdns);
        dev->mdns = NULL;
    }

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

/**
 * return true if the iam user is used by a connection.
 */
bool nc_device_user_in_use(struct nc_device_context* dev, struct nc_iam_user* user)
{
    return nc_client_connection_dispatch_user_in_use(&dev->clientConnect, user);
}


void nc_device_add_connection_events_listener(struct nc_device_context* dev, struct nc_connection_events_listener* listener, nc_connection_event_callback cb, void* userData)
{
    listener->cb = cb;
    listener->userData = userData;

    struct nc_connection_events_listener* before = dev->eventsListenerSentinel.prev;
    struct nc_connection_events_listener* after = before->next;

    before->next = listener;
    listener->next = after;
    after->prev = listener;
    listener->prev = before;

}

void nc_device_remove_connection_events_listener(struct nc_device_context* dev, struct nc_connection_events_listener* listener)
{
    struct nc_connection_events_listener* before = listener->prev;
    struct nc_connection_events_listener* after = listener->next;
    before->next = after;
    after->prev = before;
    listener->prev = listener;
    listener->next = listener;
}

void nc_device_connection_events_listener_notify(struct nc_device_context* dev, uint64_t connectionRef, enum nc_connection_event event)
{
    struct nc_connection_events_listener* iterator = dev->eventsListenerSentinel.next;

    while (iterator != &dev->eventsListenerSentinel)
    {
        // increment iterator now, such that it's allowed to remove
        // the listener from the connection in from the event handler.
        struct nc_connection_events_listener* current = iterator;
        iterator = iterator->next;

        current->cb(connectionRef, event, current->userData);
    }
}

void nc_device_add_device_events_listener(struct nc_device_context* dev, struct nc_device_events_listener* listener, nc_device_event_callback cb, void* userData)
{
    listener->cb = cb;
    listener->userData = userData;

    struct nc_device_events_listener* before = dev->deviceEventsSentinel.prev;
    struct nc_device_events_listener* after = before->next;

    before->next = listener;
    listener->next = after;
    after->prev = listener;
    listener->prev = before;

}

void nc_device_remove_device_events_listener(struct nc_device_context* dev, struct nc_device_events_listener* listener)
{
    struct nc_device_events_listener* before = listener->prev;
    struct nc_device_events_listener* after = listener->next;
    before->next = after;
    after->prev = before;
    listener->prev = listener;
    listener->next = listener;
}

void nc_device_events_listener_notify(enum nc_device_event event, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    struct nc_device_events_listener* iterator = dev->deviceEventsSentinel.next;

    while (iterator != &dev->deviceEventsSentinel)
    {
        // increment iterator now, such that it's allowed to remove
        // the listener from the connection in from the event handler.
        struct nc_device_events_listener* current = iterator;
        iterator = iterator->next;

        current->cb(event, current->userData);
    }
}
