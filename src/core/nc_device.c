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
    np_error_code ec;
    ec = nc_udp_dispatch_init(&device->udp, pl);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = nc_udp_dispatch_init(&device->secondaryUdp, pl);
    if (ec != NABTO_EC_OK) {
        nc_udp_dispatch_deinit(&device->udp);
        return ec;
    }

    ec = pl->dtlsS.create(pl, &device->dtlsServer);
    if (ec != NABTO_EC_OK) {
        nc_udp_dispatch_deinit(&device->udp);
        nc_udp_dispatch_deinit(&device->secondaryUdp);
        return ec;
    }
    nc_iam_init(&device->iam);
    nc_coap_server_init(pl, &device->coapServer);
    nc_iam_coap_register_handlers(device);
    nc_coap_client_init(pl, &device->coapClient);
    nc_attacher_init(&device->attacher, pl, device, &device->coapClient);
    nc_rendezvous_init(&device->rendezvous, pl);
    nc_stun_init(&device->stun, pl);
    nc_client_connection_dispatch_init(&device->clientConnect, pl, device);
    nc_stream_manager_init(&device->streamManager, pl);

    // TODO why are these not in init, where is deinit?
    nc_stun_coap_init(&device->stunCoap, pl, &device->coapServer, &device->stun);
    nc_rendezvous_coap_init(&device->rendezvousCoap, &device->coapServer, &device->rendezvous);

    device->eventsListenerSentinel.next = &device->eventsListenerSentinel;
    device->eventsListenerSentinel.prev = &device->eventsListenerSentinel;

    device->deviceEventsSentinel.next = &device->deviceEventsSentinel;
    device->deviceEventsSentinel.prev = &device->deviceEventsSentinel;

    device->serverPort = 4433;

    return NABTO_EC_OK;
}

void nc_device_deinit(struct nc_device_context* device) {
    struct np_platform* pl = device->pl;

    nc_stream_manager_deinit(&device->streamManager);
    nc_client_connection_dispatch_deinit(&device->clientConnect);
    nc_stun_deinit(&device->stun);
    nc_rendezvous_deinit(&device->rendezvous);
    nc_attacher_deinit(&device->attacher);
    nc_coap_client_deinit(&device->coapClient);
    nc_coap_server_deinit(&device->coapServer);
    nc_iam_deinit(&device->iam);
    pl->dtlsS.destroy(device->dtlsServer);
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

void nc_device_try_resolve_close(struct nc_device_context* dev)
{
    if (dev->clientConnsClosed && dev->isDetached) {
        np_event_queue_cancel_event(dev->pl, &dev->closeEvent);
        nc_udp_dispatch_abort(&dev->udp);
        nc_udp_dispatch_abort(&dev->secondaryUdp);
        if (dev->closeCb) {
            nc_device_close_callback cb = dev->closeCb;
            dev->closeCb = NULL;
            cb(NABTO_EC_OK, dev->closeCbData);
            return;
        }
    }
}

void nc_device_reattach(const np_error_code ec, void* data)
{
    if (ec != NABTO_EC_OK) {
        // reattach probably cancelled due to stopping
        // todo verify error handling
        return;
    }
    struct nc_device_context* dev = (struct nc_device_context*)data;
    nc_attacher_async_attach(&dev->attacher, dev->pl, &dev->attachParams, nc_device_attached_cb, dev);
}

void nc_device_detached_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    NABTO_LOG_INFO(LOG, "Device detached callback");
    nc_device_events_listener_notify(dev, NC_DEVICE_EVENT_DETACHED);
    dev->isDetached = true;
    if (!dev->stopping) {
        np_event_queue_post_timed_event(dev->pl, &dev->tEv, nc_device_get_reattach_time(dev), &nc_device_reattach, data);
    } else {
        nc_device_try_resolve_close(dev);
    }
}

void nc_device_attached_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    if (ec == NABTO_EC_OK) {
        NABTO_LOG_INFO(LOG, "Device is now attached");
        nc_device_events_listener_notify(dev, NC_DEVICE_EVENT_ATTACHED);
        dev->isDetached = false;
        dev->attachAttempts = 0;
        // wait for detach or quit.
        np_error_code ec2;
        ec2 = nc_attacher_register_detach_callback(&dev->attacher, &nc_device_detached_cb, dev);
        if ( ec2 != NABTO_EC_OK ) {
            NABTO_LOG_ERROR(LOG, "Failed to register detach callback. This should not be possible");
        }
    } else {
        NABTO_LOG_INFO(LOG, "Device failed to attached");
        dev->isDetached = true;
        if (!dev->stopping) {
            NABTO_LOG_TRACE(LOG, "Not stopping, trying to reattach");
            np_event_queue_post_timed_event(dev->pl, &dev->tEv, nc_device_get_reattach_time(dev), &nc_device_reattach, data);
        } else {
            // stopping, trying to close
            nc_device_try_resolve_close(dev);
        }
    }
}

void nc_device_stun_analysed_cb(const np_error_code ec, const struct nabto_stun_result* res, void* data)
{
    // TODO fail if closed if used
    NABTO_LOG_INFO(LOG, "Stun analysis finished with ec: %s", np_error_code_to_string(ec));
}

void nc_device_secondary_udp_bound_cb(const np_error_code ec, void* data) {
    struct nc_device_context* dev = (struct nc_device_context*)data;
    if (dev->stopping) {
        dev->clientConnsClosed = true; // client conns cannot have started
        nc_device_try_resolve_close(dev);
    }
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "nc_device failed to create secondary UDP socket. Device continues without STUN");
        return;
    }
    nc_stun_init_config_and_sockets(&dev->stun, dev->stunHost, &dev->udp, &dev->secondaryUdp);

    nc_udp_dispatch_set_stun_context(&dev->udp, &dev->stun);
    nc_udp_dispatch_set_stun_context(&dev->secondaryUdp, &dev->stun);

    // TODO: determine if we should make stun analysis on startup
    // ec2 = nc_stun_async_analyze(&dev->stun, &nc_device_stun_analysed_cb, dev);
}

void nc_device_udp_bound_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    if (dev->stopping) {
        dev->clientConnsClosed = true; // client conns cannot have started
        nc_device_try_resolve_close(dev);
    }
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "nc_device failed to bind primary UDP socket");
        nc_device_events_listener_notify(dev, NC_DEVICE_EVENT_FAILURE);
        return;
    }

    np_error_code ec2 = nc_udp_dispatch_async_bind(&dev->secondaryUdp, dev->pl, 0, &nc_device_secondary_udp_bound_cb, dev);
    if (ec2 != NABTO_EC_OK) {
        nc_udp_dispatch_abort(&dev->udp);
        nc_device_events_listener_notify(dev, NC_DEVICE_EVENT_FAILURE);
        return;
    }
    nc_udp_dispatch_set_client_connection_context(&dev->udp, &dev->clientConnect);

    nc_attacher_async_attach(&dev->attacher, dev->pl, &dev->attachParams, nc_device_attached_cb, dev);

    if (dev->enableMdns) {
        dev->pl->mdns.start(&dev->mdns, dev->pl, dev->productId, dev->deviceId, nc_device_mdns_get_port, dev);
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
    dev->stopping = false;
    dev->isDetached = true;
    dev->clientConnsClosed = false;
    dev->enableMdns = enableMdns;
    dev->stunHost = stunHost;
    dev->productId = productId;
    dev->deviceId = deviceId;

    dev->attachParams.appName = appName;
    dev->attachParams.appVersion = appVersion;
    dev->attachParams.hostname = hostname;
    dev->attachParams.udp = &dev->udp;

    dev->productId = productId;
    dev->deviceId = deviceId;

    dev->connectionRef = 0;

    np_error_code ec = nc_udp_dispatch_async_bind(&dev->udp, pl, port, &nc_device_udp_bound_cb, dev);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    nc_rendezvous_set_udp_dispatch(&dev->rendezvous, &dev->udp);

    return NABTO_EC_OK;
}

void nc_device_client_connections_closed_cb(void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    dev->clientConnsClosed = true;
    nc_device_try_resolve_close(dev);
}

void nc_device_event_close(void* data) {
    struct nc_device_context* dev = (struct nc_device_context*)data;
    nc_device_try_resolve_close(dev);
}

np_error_code nc_device_close(struct nc_device_context* dev, nc_device_close_callback cb, void* data)
{
    dev->closeCb = cb;
    dev->closeCbData = data;
    dev->stopping = true;
    dev->clientConnsClosed = false;
    np_error_code ec = nc_client_connection_dispatch_async_close(&dev->clientConnect, &nc_device_client_connections_closed_cb, dev);
    if (ec == NABTO_EC_STOPPED) {
        dev->clientConnsClosed = true;
    }
    nc_rendezvous_remove_udp_dispatch(&dev->rendezvous);
    nc_stun_deinit_sockets(&dev->stun);
    np_event_queue_cancel_timed_event(dev->pl, &dev->tEv);
    if (dev->enableMdns && dev->mdns) {
        dev->pl->mdns.stop(dev->mdns);
    }
    if (dev->isDetached) {
        // async try_resolv_close
        np_event_queue_post(dev->pl, &dev->closeEvent, &nc_device_event_close, dev);
    } else {
        nc_attacher_detach(&dev->attacher);
    }
    return NABTO_EC_OK;
}

uint32_t nc_device_get_reattach_time(struct nc_device_context* dev)
{
    uint32_t ms;
    if (dev->attachAttempts >= 19) { // 2^19s > 12h
        ms = 43200000; // 12h
    } else {
        ms = 2 << dev->attachAttempts; // 2sec^n
        ms = ms * 1000; // s to ms
        dev->attachAttempts++;
    }
    NABTO_LOG_INFO(LOG, "returning reattach time: %i, attachAttempts: %i", ms, dev->attachAttempts);
    return ms;
}

uint64_t nc_device_next_connection_ref(struct nc_device_context* dev)
{
    // TODO fail if we wrap around, highly unlikely!
    dev->connectionRef += 1;
    return dev->connectionRef;
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

void nc_device_events_listener_notify(struct nc_device_context* dev, enum nc_device_event event)
{
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
