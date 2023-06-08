#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>


#include "nabto_device_coap.h"
#include "nabto_device_defines.h"
#include "nabto_device_future.h"

#include <core/nc_connection.h>
#include <core/nc_virtual_connection.h>
#include <platform/np_allocator.h>

struct nabto_device_virtual_connection;

struct nabto_device_virtual_coap_response {
    void* payload;
    size_t payloadSize;
    uint16_t contentFormat;
    uint16_t statusCode;
};

struct nabto_device_virtual_coap_request {
    struct nabto_device_virtual_connection* connection;
    struct nabto_device_future* future;
    struct nabto_device_coap_request apiReq;
    nabto_coap_method method;
    const char** segments;
    void* payload;
    size_t payloadSize;
    uint16_t contentFormat;
    bool responseReady;
};

struct nabto_device_virtual_connection {
    struct nabto_device_context* dev;
    struct nabto_device_future* closeFuture;
    struct nc_connection* connection;
};

static void response_handler(np_error_code ec, struct nc_coap_server_request* request, void* userData);

static size_t fromHex(const char* str, uint8_t** data)
{
    size_t dataLength = strlen(str)/2;
    uint8_t* output = (uint8_t*)np_calloc(1, dataLength);
    if (output == NULL) {
        return 0;
    }
    size_t i;
    int value;
    for (i = 0; i < dataLength && sscanf(str + i * 2, "%2x", &value) == 1; i++) {
        output[i] = value;
    }
    *data = output;
    return dataLength;
}


NabtoDeviceVirtualConnection* NABTO_DEVICE_API
nabto_device_virtual_connection_new(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_virtual_connection* conn = np_calloc(1, sizeof(struct nabto_device_virtual_connection));
    if (conn != NULL) {
        conn->dev = dev;
        conn->connection = nc_virtual_connection_new(&dev->core);
    }
    return (NabtoDeviceVirtualConnection*)conn;

}


void NABTO_DEVICE_API
nabto_device_virtual_connection_free(NabtoDeviceVirtualConnection* connection)
{
    if (connection == NULL) {
        return;
    }
    struct nabto_device_virtual_connection* conn = (struct nabto_device_virtual_connection*)connection;
    struct nabto_device_context* dev = conn->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    nc_virtual_connection_destroy(conn->connection->connectionImplCtx);
    np_free(conn);
    nabto_device_threads_mutex_unlock(dev->eventMutex);

}


void NABTO_DEVICE_API
nabto_device_virtual_connection_close(NabtoDeviceVirtualConnection* connection, NabtoDeviceFuture* future)
{
    // TODO: does this do anything?
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_connection_set_device_fingerprint(NabtoDeviceVirtualConnection* connection, const char* fp)
{
    struct nabto_device_virtual_connection* conn = (struct nabto_device_virtual_connection*)connection;
    uint8_t* fpBin;
    size_t len = fromHex(fp, &fpBin);
    if (len < 32) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }
    if (!nc_virtual_connection_set_device_fingerprint(conn->connection->connectionImplCtx, fpBin)) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    };
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_connection_set_client_fingerprint(NabtoDeviceVirtualConnection* connection, const char* fp)
{
    struct nabto_device_virtual_connection* conn = (struct nabto_device_virtual_connection*)connection;
    uint8_t* fpBin;
    size_t len = fromHex(fp, &fpBin);
    if (len < 32) {
        np_free(fpBin);
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }
    if (!nc_virtual_connection_set_client_fingerprint(conn->connection->connectionImplCtx, fpBin)) {
        np_free(fpBin);
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    };
    np_free(fpBin);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceConnectionRef  NABTO_DEVICE_API
nabto_device_connection_get_connection_ref(NabtoDeviceVirtualConnection* connection)
{
    struct nabto_device_virtual_connection* conn = (struct nabto_device_virtual_connection*)connection;
    return conn->connection->connectionRef;
}


bool NABTO_DEVICE_API
nabto_device_connection_is_virtual(NabtoDevice* device, NabtoDeviceConnectionRef ref)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    bool virtual = false;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nc_connection* connection = nc_device_connection_from_ref(&dev->core, ref);
    if (connection != NULL) {
        virtual = nc_connection_is_virtual(connection);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return virtual;
}

NabtoDeviceVirtualCoapRequest* NABTO_DEVICE_API
nabto_device_virtual_coap_request_new(NabtoDeviceVirtualConnection* connection, NabtoDeviceCoapMethod method, const char** segments)
{
    struct nabto_device_virtual_connection* conn = (struct nabto_device_virtual_connection*)connection;

    struct nabto_device_virtual_coap_request* virReq = np_calloc(1, sizeof(struct nabto_device_virtual_coap_request));

    if (virReq == NULL) {
        np_free(virReq);
        return NULL;
    }
    virReq->connection = conn;
    virReq->responseReady = false;
    virReq->method = method;
    virReq->segments = segments;
    virReq->apiReq.dev = conn->dev;
    virReq->apiReq.connectionRef = conn->connection->connectionRef;
    return (NabtoDeviceVirtualCoapRequest*)virReq;
}

void NABTO_DEVICE_API
nabto_device_virtual_coap_request_free(NabtoDeviceVirtualCoapRequest* request)
{
    struct nabto_device_virtual_coap_request* req = (struct nabto_device_virtual_coap_request*)request;
    if (req->apiReq.req != NULL) {
        struct nabto_device_context* dev = req->connection->dev;
        nabto_device_threads_mutex_lock(dev->eventMutex);
        nc_coap_server_virtual_request_free(req->apiReq.req);
        nabto_device_threads_mutex_unlock(dev->eventMutex);
    }
    np_free(req->payload);
    np_free(req);

}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_coap_request_set_payload(NabtoDeviceVirtualCoapRequest* request,
                                       const void* data,
                                       size_t dataSize)
{
    struct nabto_device_virtual_coap_request* req = (struct nabto_device_virtual_coap_request*)request;
    req->payload = np_calloc(1, dataSize);
    if (req->payload == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }
    req->payloadSize = dataSize;
    memcpy(req->payload, data, dataSize);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_coap_request_set_content_format(NabtoDeviceVirtualCoapRequest* request, uint16_t format)
{
    struct nabto_device_virtual_coap_request* req = (struct nabto_device_virtual_coap_request*)request;
    req->contentFormat = format;
    return NABTO_DEVICE_EC_OK;
}

void NABTO_DEVICE_API nabto_device_virtual_coap_request_execute(NabtoDeviceVirtualCoapRequest* request, NabtoDeviceFuture* future)
{
    struct nabto_device_virtual_coap_request* req = (struct nabto_device_virtual_coap_request*)request;
    struct nabto_device_context* dev = req->connection->dev;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    req->future = fut;
    req->apiReq.req = nc_coap_server_create_virtual_request(&dev->core.coapServer, nabto_device_coap_method_to_code(req->method), req->segments, req->payload, req->payloadSize, req->contentFormat, &response_handler, req);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    if (req->apiReq.req == NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OUT_OF_MEMORY);
    }
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_coap_request_get_response_status_code(NabtoDeviceVirtualCoapRequest* request, uint16_t* statusCode)
{
    struct nabto_device_virtual_coap_request* req = (struct nabto_device_virtual_coap_request*)request;

    if (!req->responseReady) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    struct nabto_device_context* dev = req->connection->dev;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    *statusCode = nc_coap_server_response_get_code_human(req->apiReq.req);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_coap_request_get_response_content_format(NabtoDeviceVirtualCoapRequest* request, uint16_t* contentFormat)
{
    struct nabto_device_virtual_coap_request* req = (struct nabto_device_virtual_coap_request*)request;

    if (!req->responseReady) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    struct nabto_device_context* dev = req->connection->dev;
    int32_t cf;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    cf = nc_coap_server_response_get_content_format(req->apiReq.req);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    if (cf >= 0) {
        *contentFormat = (uint16_t)cf;
        return NABTO_DEVICE_EC_OK;
    } else {
        return NABTO_DEVICE_EC_UNKNOWN;
    }
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_coap_request_get_response_payload(NabtoDeviceVirtualCoapRequest* request, void** payload, size_t* payloadLength)
{
    struct nabto_device_virtual_coap_request* req = (struct nabto_device_virtual_coap_request*)request;

    if (!req->responseReady) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    struct nabto_device_context* dev = req->connection->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    nc_coap_server_request_get_payload(req->apiReq.req, payload, payloadLength);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    if(*payload == NULL) {
        return NABTO_DEVICE_EC_UNKNOWN;
    } else {
        return NABTO_DEVICE_EC_OK;
    }
}



void response_handler(np_error_code ec, struct nc_coap_server_request* request, void* userData)
{
    struct nabto_device_virtual_coap_request* req = (struct nabto_device_virtual_coap_request*)userData;
    if (ec == NABTO_EC_OK) {
        req->responseReady = true;
    }
    nabto_device_future_resolve(req->future, ec);

}
