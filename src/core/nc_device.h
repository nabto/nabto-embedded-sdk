#ifndef NC_DEVICE_H
#define NC_DEVICE_H

#include <core/nc_attacher.h>
#include <core/nc_stream_manager.h>
#include <core/nc_client_connect_dispatch.h>
#include <core/nc_stun.h>

#include <platform/np_error_code.h>

typedef void (*nc_device_close_callback)(const np_error_code ec, void* data);

struct nc_device_context {
    struct np_platform* pl;
    bool stopping;
    struct nc_udp_dispatch_context udp;
    struct nc_attach_parameters attachParams;
    struct nc_attach_context attacher;
    struct nc_stream_manager_context streamManager;
    struct nc_client_connect_dispatch_context clientConnect;
    struct nc_stun_context stun;

    const char* stunHost;
    
    nc_device_close_callback closeCb;
    void* closeCbData;
};

np_error_code nc_device_start(struct nc_device_context* dev, struct np_platform* pl,
                              const char* appName, const char* appVersion,
                              const char* productId, const char* deviceId,
                              const char* hostname, const char* stunHost);

np_error_code nc_device_close(struct nc_device_context* dev, nc_device_close_callback cb, void* data);

#endif // NC_DEVICE_H
