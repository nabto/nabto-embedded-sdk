#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "nabto_device_defines.h"
#include "nabto_device_future.h"

#include <core/nc_attacher.h>

#include <platform/np_allocator.h>
#include <nn/string.h>

struct nabto_device_turn_credential_request {
    struct nabto_device_context* dev;
    struct nc_attacher_get_turn_server_context turnCtx;
    struct nabto_device_future* future;
};

NabtoDeviceTurnCredentialRequest* NABTO_DEVICE_API
nabto_device_turn_credential_request_new(NabtoDevice* device)
{
    struct nabto_device_turn_credential_request* req = np_calloc(1, sizeof(struct nabto_device_turn_credential_request));
    if (req != NULL) {
        struct nabto_device_context* dev = (struct nabto_device_context*)device;
        req->dev = dev;
        nc_attacher_turn_ctx_init(&req->turnCtx);
    }
    return (NabtoDeviceTurnCredentialRequest*)req;
}


void NABTO_DEVICE_API
nabto_device_turn_credential_request_free(NabtoDeviceTurnCredentialRequest* turn)
{
    struct nabto_device_turn_credential_request* req = (struct nabto_device_turn_credential_request*)turn;
    struct nabto_device_context* dev = req->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    nc_attacher_turn_ctx_deinit(&req->turnCtx);
    np_free(req);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

static void turn_req_send_callback(np_error_code ec, void* userData)
{
    struct nabto_device_turn_credential_request* req = userData;
    nabto_device_future_resolve(req->future, ec);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_turn_credential_request_send(const char* identifier, NabtoDeviceTurnCredentialRequest* turn, NabtoDeviceFuture* future)
{
    struct nabto_device_future* f = (struct nabto_device_future*)future;
    struct nabto_device_turn_credential_request* req = (struct nabto_device_turn_credential_request*)turn;
    struct nabto_device_context* dev = req->dev;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    nabto_device_future_reset(f);

    if (req->future != NULL) {
        nabto_device_future_resolve(f, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    } else {
        req->future = f;

        np_error_code ec = nc_attacher_get_turn_server(&dev->core.attacher, &req->turnCtx, identifier, turn_req_send_callback, req);

        if (ec != NABTO_EC_OK) {
            nabto_device_future_resolve(f, ec);
        }
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_turn_credential_get_results_count(NabtoDeviceTurnCredentialRequest* turn, size_t* count)
{
    struct nabto_device_turn_credential_request* req = (struct nabto_device_turn_credential_request*)turn;
    if (req->turnCtx.turnServers.used == 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    *count = req->turnCtx.turnServers.used;
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_turn_credential_get_result(NabtoDeviceTurnCredentialRequest* turn, size_t index, NabtoDeviceTurnCredentialResult** result)
{
    struct nabto_device_turn_credential_request* req = (struct nabto_device_turn_credential_request*)turn;
    if (req->turnCtx.turnServers.used == 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    if (req->turnCtx.turnServers.used <= index) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }
    // nn_vector_get(&req->turnCtx.turnServers, index, (void*)result);
    *result = nn_vector_reference(&req->turnCtx.turnServers, index);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_turn_credential_get_username(NabtoDeviceTurnCredentialResult* result, char** username)
{
    struct nc_attacher_turn_server* server = (struct nc_attacher_turn_server*)result;
    *username = server->username;
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_turn_credential_get_credential(NabtoDeviceTurnCredentialResult* result, char** credential)
{
    struct nc_attacher_turn_server* server = (struct nc_attacher_turn_server*)result;
    *credential = server->credential;
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_turn_credential_get_ttl(NabtoDeviceTurnCredentialResult* result, uint32_t* ttl)
{
    struct nc_attacher_turn_server* server = (struct nc_attacher_turn_server*)result;
    *ttl = server->ttl;
    return NABTO_DEVICE_EC_OK;

}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_turn_credential_get_urls(NabtoDeviceTurnCredentialResult* result, char*** urls, size_t* urlsLen)
{
    struct nc_attacher_turn_server* server = (struct nc_attacher_turn_server*)result;
    *urls = server->urls;
    *urlsLen = server->urlsLen;
    return NABTO_DEVICE_EC_OK;
}
