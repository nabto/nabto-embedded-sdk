#include "nc_device.h"
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_CORE

void nc_device_attached_cb(const np_error_code ec, void* data);

void nc_device_udp_destroyed_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    NABTO_LOG_INFO(LOG, "UDP dispatcher destroyed");
    if (dev->closeCb) {
        nc_device_close_callback cb = dev->closeCb;
        dev->closeCb = NULL;
        cb(ec, dev->closeCbData);
    }
}

void nc_device_detached_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    NABTO_LOG_INFO(LOG, "Device detached callback");
    if (!dev->stopping) {
        nc_attacher_async_attach(&dev->attacher, dev->pl, &dev->attachParams, nc_device_attached_cb, dev);
    } else {
        nc_udp_dispatch_async_destroy(&dev->udp, &nc_device_udp_destroyed_cb, dev);
    }
}

void nc_device_attached_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    if (ec == NABTO_EC_OK) {
        NABTO_LOG_INFO(LOG, "Device is now attached");
    } else {
        NABTO_LOG_INFO(LOG, "Device failed to attached");
       if (dev->stopping) {
           nc_udp_dispatch_async_destroy(&dev->udp, &nc_device_udp_destroyed_cb, dev);
       } else {
           NABTO_LOG_TRACE(LOG, "Not stopping, trying to reattach");
           nc_attacher_async_attach(&dev->attacher, dev->pl, &dev->attachParams, nc_device_attached_cb, dev);
       }
    }
}

void nc_device_stun_analysed_cb(const np_error_code ec, const struct nabto_stun_result* res, void* data)
{
    NABTO_LOG_INFO(LOG, "Stun analysis finished with ec: %s", np_error_code_to_string(ec));
}

void nc_device_udp_created_cb(const np_error_code ec, void* data)
{
    struct nc_device_context* dev = (struct nc_device_context*)data;
    np_error_code ec2;
    NABTO_LOG_TRACE(LOG, "nc_device_udp_created_cb");
    if (dev->stopping) {
        nc_udp_dispatch_async_destroy(&dev->udp, &nc_device_udp_destroyed_cb, dev);
        return;
    }
    nc_udp_dispatch_set_client_connect_context(&dev->udp, &dev->clientConnect);
    
    ec2 = nc_attacher_register_detatch_callback(&dev->attacher, &nc_device_detached_cb, dev);
    nc_attacher_async_attach(&dev->attacher, dev->pl, &dev->attachParams, nc_device_attached_cb, &dev);
    
    nc_stun_init(&dev->stun, dev->pl, dev->stunHost, &dev->udp);
    ec2 = nc_stun_async_analyze(&dev->stun, &nc_device_stun_analysed_cb, dev);
}

np_error_code nc_device_start(struct nc_device_context* dev, struct np_platform* pl,
                              const char* appName, const char* appVersion,
                              const char* productId, const char* deviceId,
                              const char* hostname, const char* stunHost)
{
    NABTO_LOG_INFO(LOG, "Starting Nabto Device");
    dev->pl = pl;
    dev->stopping = false;
    dev->stunHost = stunHost;
    nc_stream_manager_init(&dev->streamManager, pl);
    nc_client_connect_dispatch_init(&dev->clientConnect, pl, &dev->streamManager);

    dev->attachParams.appName = appName;
    dev->attachParams.appVersion = appVersion;
    dev->attachParams.hostname = hostname;
    dev->attachParams.udp = &dev->udp;

    nc_udp_dispatch_async_create(&dev->udp, pl, &nc_device_udp_created_cb, dev);
    
    return NABTO_EC_OK;
}

np_error_code nc_device_close(struct nc_device_context* dev, nc_device_close_callback cb, void* data)
{
    dev->closeCb = cb;
    dev->closeCbData = data;
    dev->stopping = true;
    nc_attacher_detach(&dev->attacher);
}
