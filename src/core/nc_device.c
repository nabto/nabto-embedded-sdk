#include "nc_device.h"
#include "nc_iam_coap.h"
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_CORE

void nc_device_attached_cb(const np_error_code ec, void* data);
uint32_t nc_device_get_reattach_time(struct nc_device_context* ctx);


void nc_device_init(struct nc_device_context* device, struct np_platform* pl)
{
    device->pl = pl;
    nc_iam_init(&device->iam);
    nc_coap_server_init(pl, &device->coapServer);
    nc_iam_coap_register_handlers(device);
    nc_coap_client_init(pl, &device->coapClient);
    nc_attacher_init(&device->attacher, pl, &device->coapClient);
}

void nc_device_deinit(struct nc_device_context* device) {
    nc_attacher_deinit(&device->attacher);
    nc_coap_client_deinit(&device->coapClient);
    nc_coap_server_deinit(&device->coapServer);
    nc_iam_deinit(&device->iam);
}

void nc_device_set_keys(struct nc_device_context* device, const unsigned char* publicKeyL, size_t publicKeySize, const unsigned char* privateKeyL, size_t privateKeySize)
{
    nc_attacher_set_keys(&device->attacher, publicKeyL, publicKeySize, privateKeyL, privateKeySize);
}

void nc_device_udp_destroyed_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    NABTO_LOG_INFO(LOG, "UDP dispatcher destroyed");
    if (dev->closeCb) {
        nc_device_close_callback cb = dev->closeCb;
        dev->closeCb = NULL;
        cb(ec, dev->closeCbData);
        return;
    }
}

void nc_device_reattach(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    nc_attacher_async_attach(&dev->attacher, dev->pl, &dev->attachParams, nc_device_attached_cb, dev);
}

void nc_device_detached_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    NABTO_LOG_INFO(LOG, "Device detached callback");
    if (!dev->stopping) {
        np_event_queue_post_timed_event(dev->pl, &dev->tEv, nc_device_get_reattach_time(dev), &nc_device_reattach, data);
    } else {
        nc_udp_dispatch_async_destroy(&dev->udp, &nc_device_udp_destroyed_cb, dev);
    }
}

void nc_device_attached_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    if (ec == NABTO_EC_OK) {
        NABTO_LOG_INFO(LOG, "Device is now attached");
        dev->attachAttempts = 0;
        // wait for detach or quit.
        np_error_code ec2;
        ec2 = nc_attacher_register_detach_callback(&dev->attacher, &nc_device_detached_cb, dev);
        if ( ec2 != NABTO_EC_OK ) {
            // TODO: handle impossible error
        }
    } else {
        NABTO_LOG_INFO(LOG, "Device failed to attached");
       if (dev->stopping) {
           nc_udp_dispatch_async_destroy(&dev->udp, &nc_device_udp_destroyed_cb, dev);
       } else {
           NABTO_LOG_TRACE(LOG, "Not stopping, trying to reattach");
           np_event_queue_post_timed_event(dev->pl, &dev->tEv, nc_device_get_reattach_time(dev), &nc_device_reattach, data);
       }
    }
}

void nc_device_stun_analysed_cb(const np_error_code ec, const struct nabto_stun_result* res, void* data)
{
    NABTO_LOG_INFO(LOG, "Stun analysis finished with ec: %s", np_error_code_to_string(ec));
}

void nc_device_secondary_udp_created_cb(const np_error_code ec, void* data) {
    struct nc_device_context* dev = (struct nc_device_context*)data;
    nc_stun_init(&dev->stun, dev->pl, dev->stunHost, &dev->udp, &dev->secondaryUdp);

    nc_udp_dispatch_set_stun_context(&dev->udp, &dev->stun);
    nc_udp_dispatch_set_stun_context(&dev->secondaryUdp, &dev->stun);

    // TODO: determine if we should make stun analysis on startup
    // ec2 = nc_stun_async_analyze(&dev->stun, &nc_device_stun_analysed_cb, dev);
}

void nc_device_udp_created_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    NABTO_LOG_TRACE(LOG, "nc_device_udp_created_cb");
    if (dev->stopping) {
        nc_udp_dispatch_async_destroy(&dev->udp, &nc_device_udp_destroyed_cb, dev);
        return;
    }
    nc_udp_dispatch_set_client_connection_context(&dev->udp, &dev->clientConnect);

    nc_attacher_async_attach(&dev->attacher, dev->pl, &dev->attachParams, nc_device_attached_cb, dev);

    nc_udp_dispatch_async_create(&dev->secondaryUdp, dev->pl, 0, &nc_device_secondary_udp_created_cb, dev);
}

np_error_code nc_device_start(struct nc_device_context* dev,
                              const char* appName, const char* appVersion,
                              const char* productId, const char* deviceId,
                              const char* hostname, const char* stunHost,
                              const uint16_t port)
{
    struct np_platform* pl = dev->pl;
    NABTO_LOG_INFO(LOG, "Starting Nabto Device");
    dev->stopping = false;
    dev->stunHost = stunHost;
    nc_stream_manager_init(&dev->streamManager, pl);
    nc_client_connection_dispatch_init(&dev->clientConnect, pl, dev);

    dev->attachParams.appName = appName;
    dev->attachParams.appVersion = appVersion;
    dev->attachParams.hostname = hostname;
    dev->attachParams.udp = &dev->udp;

    dev->connectionRef = 0;

    nc_udp_dispatch_async_create(&dev->udp, pl, port, &nc_device_udp_created_cb, dev);
    nc_rendezvous_init(&dev->rendezvous, pl, &dev->udp);

    nc_stun_coap_init(&dev->stunCoap, pl, &dev->coapServer, &dev->stun);
    nc_rendezvous_coap_init(&dev->rendezvousCoap, &dev->coapServer, &dev->rendezvous);

    return NABTO_EC_OK;
}

np_error_code nc_device_close(struct nc_device_context* dev, nc_device_close_callback cb, void* data)
{
    dev->closeCb = cb;
    dev->closeCbData = data;
    dev->stopping = true;
    nc_attacher_detach(&dev->attacher);
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

bool nc_device_user_in_use(struct nc_device_context* dev, struct nc_iam_user* user)
{
    return nc_client_connection_dispatch_user_in_use(&dev->clientConnect, user);
}
