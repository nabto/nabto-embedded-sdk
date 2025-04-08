#include <nabto/nabto_device.h>
#include <nabto/nabto_device_virtual.h>

#include <api/nabto_device_error.h>

#include "nabto_device_coap.h"
#include "nabto_device_defines.h"
#include "nabto_device_future.h"

#include <core/nc_connection.h>
#include <core/nc_virtual_connection.h>
#include <core/nc_virtual_stream.h>
#include <platform/np_allocator.h>
#include <platform/np_util.h>
#include <platform/np_completion_event.h>

#include <nn/string.h>

struct nabto_device_virtual_connection;

struct nabto_device_virtual_stream {
    struct nc_stream_context* stream;
    struct nabto_device_context* device;
    struct nabto_device_virtual_connection* connection;

    struct nabto_device_future* openFuture; // resolves open when server has accepted/freed the stream
    struct np_completion_event openEv;

    struct nabto_device_future* readFuture; // Resolves a virtual stream read when real stream writes data
    struct np_completion_event readEv;

    struct nabto_device_future* writeFuture; // Resolves a virtual stream write when real stream has read data
    struct np_completion_event writeEv;

    struct nabto_device_future* closeFuture;
    struct np_completion_event closeEv;



};

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
    char* path;
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

static void stream_opened(np_error_code ec, void* userdata);
void write_completed(np_error_code ec, void* userdata);
void read_completed(np_error_code ec, void* userdata);
void close_completed(np_error_code ec, void* userdata);

NabtoDeviceVirtualConnection* NABTO_DEVICE_API
nabto_device_virtual_connection_new(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nc_connection* coreConn = nc_virtual_connection_new(&dev->core);

    if (coreConn == NULL) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return NULL;
    }
    struct nabto_device_virtual_connection* conn = np_calloc(1, sizeof(struct nabto_device_virtual_connection));
    if (conn != NULL) {
        conn->dev = dev;
        conn->connection = coreConn;
    }
    else {
        nc_virtual_connection_destroy(coreConn->connectionImplCtx);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
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
    if (strlen(fp) != 64) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }
    uint8_t* fpBin = (uint8_t*)np_calloc(1, 32);

    if (!np_hex_to_data(fp, fpBin, 32)) {
        np_free(fpBin);
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }
    if (!nc_virtual_connection_set_device_fingerprint(conn->connection->connectionImplCtx, fpBin)) {
        np_free(fpBin);
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    };
    np_free(fpBin);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_connection_set_client_fingerprint(NabtoDeviceVirtualConnection* connection, const char* fp)
{
    struct nabto_device_virtual_connection* conn = (struct nabto_device_virtual_connection*)connection;
    uint8_t* fpBin = (uint8_t*)np_calloc(1, 32);

    if (!np_hex_to_data(fp, fpBin, 32)) {
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


NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_device_fingerprint(NabtoDevice* device, NabtoDeviceConnectionRef ref, char** fingerprint)
{
    if (nabto_device_connection_is_virtual(device, ref)) {
        *fingerprint = NULL;
        struct nabto_device_context* dev = (struct nabto_device_context*)device;
        NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
        nabto_device_threads_mutex_lock(dev->eventMutex);

        uint8_t deviceFingerprint[32];

        struct nc_connection* connection = nc_device_connection_from_ref(&dev->core, ref);

        if (connection == NULL || !nc_connection_get_device_fingerprint(connection, deviceFingerprint)) {
            ec = NABTO_EC_INVALID_CONNECTION;
        } else {
            *fingerprint = np_calloc(1,64);
            np_data_to_hex(deviceFingerprint, 32, *fingerprint);
        }

        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return ec;
    } else {
        return nabto_device_get_device_fingerprint(device, fingerprint);
    }
}


/**** VIRTUAL COAP REQUESTS ******/

NabtoDeviceVirtualCoapRequest* NABTO_DEVICE_API
nabto_device_virtual_coap_request_new(NabtoDeviceVirtualConnection* connection, NabtoDeviceCoapMethod method, const char* path)
{
    struct nabto_device_virtual_connection* conn = (struct nabto_device_virtual_connection*)connection;

    struct nabto_device_virtual_coap_request* virReq = np_calloc(1, sizeof(struct nabto_device_virtual_coap_request));

    if (virReq == NULL) {
        np_free(virReq);
        return NULL;
    }

    virReq->connection = conn;
    virReq->responseReady = false;
    virReq->method = nabto_device_coap_method_to_code(method);
    virReq->path = nn_strdup(path, np_allocator_get());
    virReq->apiReq.dev = conn->dev;
    virReq->apiReq.connectionRef = conn->connection->connectionRef;
    size_t pathLen = strlen(virReq->path);
    if (virReq->path[pathLen-1] == '/') {
        // URL has trailing '/'
        virReq->path[pathLen-1] = 0;
        pathLen--;
    }
    size_t segmentCount = 0;
    for (size_t i = 0; i < pathLen; i++) {
        if (virReq->path[i] == '/') {
            segmentCount++;
        }
    }
    virReq->segments = np_calloc(segmentCount+1, sizeof(char*)); // count +1 for NULL termination
    size_t index = 0;
    for (size_t i = 0; i < pathLen; i++) {
        if (virReq->path[i] == '/') {
            virReq->segments[index] = &(virReq->path[i+1]);
            virReq->path[i] = 0;
            index++;
        }
    }

    return (NabtoDeviceVirtualCoapRequest*)virReq;
}

void NABTO_DEVICE_API
nabto_device_virtual_coap_request_free(NabtoDeviceVirtualCoapRequest* request)
{
    struct nabto_device_virtual_coap_request* req = (struct nabto_device_virtual_coap_request*)request;
    if (req->apiReq.req != NULL) {
        struct nabto_device_context* dev = req->apiReq.dev;
        nabto_device_threads_mutex_lock(dev->eventMutex);
        nc_coap_server_virtual_request_free(req->apiReq.req);
        nabto_device_threads_mutex_unlock(dev->eventMutex);
    }
    np_free(req->path);
    np_free(req->segments);
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
    req->apiReq.req = nc_coap_server_create_virtual_request(&dev->core.coapServer, req->connection->connection, req->method, req->segments, req->payload, req->payloadSize, req->contentFormat, &response_handler, req);
    if (req->apiReq.req == NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OUT_OF_MEMORY);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_virtual_coap_request_get_response_status_code(NabtoDeviceVirtualCoapRequest* request, uint16_t* statusCode)
{
    struct nabto_device_virtual_coap_request* req = (struct nabto_device_virtual_coap_request*)request;

    if (!req->responseReady) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    struct nabto_device_context* dev = req->connection->dev;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    ec = nc_coap_server_response_get_code_human(req->apiReq.req, statusCode);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
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
    }
    else {
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
    nc_coap_server_response_get_payload(req->apiReq.req, payload, payloadLength);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    if (*payload == NULL) {
        return NABTO_DEVICE_EC_UNKNOWN;
    }
    else {
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


/**** VIRTUAL STREAMING ******/


NabtoDeviceVirtualStream* NABTO_DEVICE_API
nabto_device_virtual_stream_new(NabtoDeviceVirtualConnection* connection)
{
    struct nabto_device_virtual_connection* conn = (struct nabto_device_virtual_connection*)connection;

    struct nabto_device_virtual_stream* virStream = np_calloc(1, sizeof(struct nabto_device_virtual_stream));

    if (virStream == NULL) {
        return NULL;
    }
    virStream->connection = conn;
    virStream->device = conn->dev;
    return (NabtoDeviceVirtualStream*)virStream;
}



void NABTO_DEVICE_API
nabto_device_virtual_stream_free(NabtoDeviceVirtualStream* stream)
{
    struct nabto_device_virtual_stream* str = (struct nabto_device_virtual_stream*)stream;
    struct nabto_device_context* dev = str->device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    nc_virtual_stream_destroy(str->stream);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    np_free(str);
}


void NABTO_DEVICE_API
nabto_device_virtual_stream_open(NabtoDeviceVirtualStream* stream, NabtoDeviceFuture* future, uint32_t port)
{
    struct nabto_device_virtual_stream* str = (struct nabto_device_virtual_stream*)stream;
    struct nabto_device_context* dev = str->device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);
    str->openFuture = fut;
    np_completion_event_init(&str->device->pl.eq, &str->openEv, &stream_opened, str);

    str->stream = nc_stream_manager_accept_virtual_stream(&dev->core.streamManager, str->connection->connection, port, &str->openEv);
    if (str->stream == NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OUT_OF_MEMORY);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}


void NABTO_DEVICE_API
nabto_device_virtual_stream_read_all(NabtoDeviceVirtualStream* stream,
    NabtoDeviceFuture* future,
    void* buffer,
    size_t bufferLength,
    size_t* readLength)
{
    struct nabto_device_virtual_stream* str = (struct nabto_device_virtual_stream*)stream;
    struct nabto_device_context* dev = str->device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);
    if (str->readFuture != NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
        return;
    }
    str->readFuture = fut;
    np_completion_event_init(&str->device->pl.eq, &str->readEv, &read_completed, str);
    nc_virtual_stream_client_async_read_all(str->stream, buffer, bufferLength, readLength, &str->readEv);

    nabto_device_threads_mutex_unlock(dev->eventMutex);

}


void NABTO_DEVICE_API
nabto_device_virtual_stream_read_some(NabtoDeviceVirtualStream* stream,
    NabtoDeviceFuture* future,
    void* buffer,
    size_t bufferLength,
    size_t* readLength)
{
    struct nabto_device_virtual_stream* str = (struct nabto_device_virtual_stream*)stream;
    struct nabto_device_context* dev = str->device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);
    if (str->readFuture != NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
        return;
    }
    str->readFuture = fut;
    np_completion_event_init(&str->device->pl.eq, &str->readEv, &read_completed, str);
    nc_virtual_stream_client_async_read_some(str->stream, buffer, bufferLength, readLength, &str->readEv);

    nabto_device_threads_mutex_unlock(dev->eventMutex);

}


void NABTO_DEVICE_API
nabto_device_virtual_stream_write(NabtoDeviceVirtualStream* stream,
    NabtoDeviceFuture* future,
    const void* buffer,
    size_t bufferLength)
{
    struct nabto_device_virtual_stream* str = (struct nabto_device_virtual_stream*)stream;
    struct nabto_device_context* dev = str->device;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);
    if (str->writeFuture != NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
        return;
    }
    str->writeFuture = fut;
    np_completion_event_init(&str->device->pl.eq, &str->writeEv, &write_completed, str);
    nc_virtual_stream_client_async_write(str->stream, buffer, bufferLength, &str->writeEv);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

void NABTO_DEVICE_API
nabto_device_virtual_stream_close(NabtoDeviceVirtualStream* stream, NabtoDeviceFuture* future)
{
    struct nabto_device_virtual_stream* str = (struct nabto_device_virtual_stream*)stream;
    struct nabto_device_context* dev = str->device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);
    if (str->closeFuture != NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
        return;
    }
    str->closeFuture = fut;
    np_completion_event_init(&str->device->pl.eq, &str->closeEv, &close_completed, str);

    nc_virtual_stream_client_async_close(str->stream, &str->closeEv);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}


void NABTO_DEVICE_API
nabto_device_virtual_stream_abort(NabtoDeviceVirtualStream* stream)
{
    struct nabto_device_virtual_stream* str = (struct nabto_device_virtual_stream*)stream;
    struct nabto_device_context* dev = str->device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    nc_virtual_stream_client_stop(str->stream);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}



void stream_opened(np_error_code ec, void* userdata)
{
    struct nabto_device_virtual_stream* str = (struct nabto_device_virtual_stream*)userdata;
    np_completion_event_deinit(&str->openEv);
    nabto_device_future_resolve(str->openFuture, nabto_device_error_core_to_api(ec));
    str->openFuture = NULL;
}


void write_completed(np_error_code ec, void* userdata)
{
    struct nabto_device_virtual_stream* str = (struct nabto_device_virtual_stream*)userdata;
    np_completion_event_deinit(&str->writeEv);
    nabto_device_future_resolve(str->writeFuture, nabto_device_error_core_to_api(ec));
    str->writeFuture = NULL;
}

void read_completed(np_error_code ec, void* userdata)
{
    struct nabto_device_virtual_stream* str = (struct nabto_device_virtual_stream*)userdata;
    np_completion_event_deinit(&str->readEv);
    nabto_device_future_resolve(str->readFuture, nabto_device_error_core_to_api(ec));
    str->readFuture = NULL;
}

void close_completed(np_error_code ec, void* userdata)
{
    struct nabto_device_virtual_stream* str = (struct nabto_device_virtual_stream*)userdata;
    np_completion_event_deinit(&str->closeEv);
    nabto_device_future_resolve(str->closeFuture, nabto_device_error_core_to_api(ec));
    str->closeFuture = NULL;
}
