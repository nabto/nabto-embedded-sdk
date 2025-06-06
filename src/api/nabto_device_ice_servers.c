#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "nabto_device_defines.h"
#include "nabto_device_future.h"

#include <core/nc_attacher.h>

#include <nn/string.h>
#include <platform/np_allocator.h>

struct nabto_device_ice_server_request {
    struct nabto_device_context* dev;
    struct nc_attacher_request_ice_servers_context turnCtx;
    struct nabto_device_future* future;
};

NabtoDeviceIceServersRequest* NABTO_DEVICE_API
nabto_device_ice_servers_request_new(NabtoDevice* device)
{
    struct nabto_device_ice_server_request* req = np_calloc(1, sizeof(struct nabto_device_ice_server_request));
    if (req != NULL) {
        struct nabto_device_context* dev = (struct nabto_device_context*)device;
        req->dev = dev;
        nc_attacher_ice_servers_ctx_init(&req->turnCtx, &dev->core.attacher);
    }
    return (NabtoDeviceIceServersRequest*)req;
}


void NABTO_DEVICE_API
nabto_device_ice_servers_request_free(NabtoDeviceIceServersRequest* request)
{
    struct nabto_device_ice_server_request* req = (struct nabto_device_ice_server_request*)request;
    struct nabto_device_context* dev = req->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    nc_attacher_ice_servers_ctx_deinit(&req->turnCtx);
    np_free(req);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

static void turn_req_send_callback(np_error_code ec, void* userData)
{
    struct nabto_device_ice_server_request* req = userData;
    nabto_device_future_resolve(req->future, ec);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_ice_servers_request_send(const char* identifier, NabtoDeviceIceServersRequest* request, NabtoDeviceFuture* future)
{
    struct nabto_device_future* f = (struct nabto_device_future*)future;
    struct nabto_device_ice_server_request* req = (struct nabto_device_ice_server_request*)request;
    struct nabto_device_context* dev = req->dev;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    nabto_device_future_reset(f);

    if (req->future != NULL) {
        nabto_device_future_resolve(f, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    } else {
        req->future = f;

        np_error_code ec = nc_attacher_request_ice_servers(&req->turnCtx, identifier, turn_req_send_callback, req);

        if (ec != NABTO_EC_OK) {
            nabto_device_future_resolve(f, ec);
        }
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return NABTO_DEVICE_EC_OK;
}

size_t NABTO_DEVICE_API
nabto_device_ice_servers_request_get_server_count(NabtoDeviceIceServersRequest* request)
{
    struct nabto_device_ice_server_request* req = (struct nabto_device_ice_server_request*)request;
    return nn_vector_size(&req->turnCtx.iceServers);
}

const char* NABTO_DEVICE_API
nabto_device_ice_servers_request_get_username(NabtoDeviceIceServersRequest* request, size_t index)
{
    struct nabto_device_ice_server_request* req = (struct nabto_device_ice_server_request*)request;
    struct nc_attacher_ice_server* server = nn_vector_reference(&req->turnCtx.iceServers, index);
    if (server != NULL) {
        return server->username;
    }
    return NULL;
}

const char* NABTO_DEVICE_API
nabto_device_ice_servers_request_get_credential(NabtoDeviceIceServersRequest* request, size_t index)
{
    struct nabto_device_ice_server_request* req = (struct nabto_device_ice_server_request*)request;
    struct nc_attacher_ice_server* server = nn_vector_reference(&req->turnCtx.iceServers, index);
    if (server != NULL) {
        return server->credential;
    }
    return NULL;
}

size_t NABTO_DEVICE_API
nabto_device_ice_servers_request_get_urls_count(NabtoDeviceIceServersRequest* request, size_t index)
{
    struct nabto_device_ice_server_request* req = (struct nabto_device_ice_server_request*)request;
    struct nc_attacher_ice_server* server = nn_vector_reference(&req->turnCtx.iceServers, index);
    if (server != NULL) {
        return nn_vector_size(&server->urls);
    }
    return 0;
}


const char* NABTO_DEVICE_API
nabto_device_ice_servers_request_get_url(NabtoDeviceIceServersRequest* request, size_t serverIndex, size_t urlIndex)
{
    struct nabto_device_ice_server_request* req = (struct nabto_device_ice_server_request*)request;
    struct nc_attacher_ice_server* server = nn_vector_reference(&req->turnCtx.iceServers, serverIndex);
    if (server != NULL) {
        char* url = NULL;
        nn_vector_get(&server->urls, urlIndex, &url);
        return url;
    }
    return NULL;

}
