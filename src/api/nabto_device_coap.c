#include "nabto_device_coap.h"

#include <api/nabto_device_defines.h>

#include <api/nabto_api_future_queue.h>
#include <api/nabto_device_future.h>

#include <stdlib.h>

/*******************************************
 * COAP API Start
 *******************************************/

NabtoDeviceError NABTO_DEVICE_API
nabto_device_coap_add_resource(NabtoDevice* device,
                               NabtoDeviceCoapMethod method,
                               const char** pathSegments,
                               NabtoDeviceCoapResourceHandler handler,
                               void* userData)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_coap_resource* resource = (struct nabto_device_coap_resource*)malloc(sizeof(struct nabto_device_coap_resource));

    resource->dev = dev;
    resource->handler = handler;
    resource->userData = userData;

    nabto_device_threads_mutex_lock(dev->eventMutex);

    nabto_coap_server_add_resource(nc_coap_server_get_server(&dev->core.coap), nabto_device_coap_method_to_code(method), pathSegments, &nabto_device_coap_resource_handler, resource);

    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return NABTO_DEVICE_EC_OK;
}

/* NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_notify_observers(NabtoDeviceCoapResource* resource) */
/* { */
/*     struct nabto_device_coap_resource* reso = (struct nabto_device_coap_resource*)resource; */
/*     nabto_device_threads_mutex_lock(reso->dev->eventMutex); */
/*     // TODO: implement observables */
/*     //nabto_coap_server_notify_observers(nc_coap_server_get_server(&reso->dev->core.coap), reso->res); */
/*     nabto_device_threads_mutex_unlock(reso->dev->eventMutex); */
/*     return NABTO_DEVICE_EC_OK; */
/* } */

NabtoDeviceCoapResponse* NABTO_DEVICE_API nabto_device_coap_create_response(NabtoDeviceCoapRequest* request)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;

    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    struct nabto_coap_server_response* resp = nabto_coap_server_create_response(req->req);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);

    struct nabto_device_coap_response* response = (struct nabto_device_coap_response*)malloc(sizeof(struct nabto_device_coap_response));
    response->resp = resp;
    response->dev = req->dev;
    response->req = req;
    return (NabtoDeviceCoapResponse*)response;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_set_code(NabtoDeviceCoapResponse* response, uint16_t code)
{
    struct nabto_device_coap_response* resp = (struct nabto_device_coap_response*)response;
    nabto_device_threads_mutex_lock(resp->dev->eventMutex);
    nabto_coap_server_response_set_code(resp->resp, nabto_coap_uint16_to_code(code));
    nabto_device_threads_mutex_unlock(resp->dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_set_payload(NabtoDeviceCoapResponse* response,
                                                        const void* data, size_t dataSize)
{
    struct nabto_device_coap_response* resp = (struct nabto_device_coap_response*)response;
    nabto_device_threads_mutex_lock(resp->dev->eventMutex);
    nabto_coap_server_response_set_payload(resp->resp, data, dataSize);
    nabto_device_threads_mutex_unlock(resp->dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_set_content_format(NabtoDeviceCoapResponse* response, uint16_t format)
{
    struct nabto_device_coap_response* resp = (struct nabto_device_coap_response*)response;
    nabto_device_threads_mutex_lock(resp->dev->eventMutex);
    nabto_coap_server_response_set_content_format(resp->resp, format);
    nabto_device_threads_mutex_unlock(resp->dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_ready(NabtoDeviceCoapResponse* response)
{
    struct nabto_device_coap_response* resp = (struct nabto_device_coap_response*)response;
    nabto_device_threads_mutex_lock(resp->dev->eventMutex);
    nabto_coap_server_response_ready(resp->resp);
    nabto_device_threads_mutex_unlock(resp->dev->eventMutex);
    free(resp->req);
    free(resp);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_request_get_content_format(NabtoDeviceCoapRequest* request,
                                                              uint16_t* contentFormat)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    bool res = nabto_coap_server_request_get_content_format(req->req, contentFormat);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    if (res) {
        return NABTO_DEVICE_EC_OK;
    } else {
        return NABTO_DEVICE_EC_FAILED;
    }
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_request_get_payload(NabtoDeviceCoapRequest* request,
                                                       void** payload, size_t* payloadLength)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    nabto_coap_server_request_get_payload(req->req, payload, payloadLength);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    if(*payload == NULL) {
        return NABTO_DEVICE_EC_FAILED;
    } else {
        return NABTO_DEVICE_EC_OK;
    }
}

NabtoDeviceConnectionRef nabto_device_coap_request_get_connection_ref(NabtoDeviceCoapRequest* request)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    struct nc_client_connection* connection = (struct nc_client_connection*)nabto_coap_server_request_get_connection(req->req);
    NabtoDeviceConnectionRef ref;
    if (connection != NULL) {
        ref= connection->connectionRef;
    } else {
        ref = 0;
    }
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    return ref;
}

const char* NABTO_DEVICE_API nabto_device_coap_request_get_parameter(NabtoDeviceCoapRequest* request, const char* parameterName)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    const char* value;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    value = nabto_coap_server_request_get_parameter(req->req, parameterName);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    return value;
}

/*******************************************
 * COAP API End
 *******************************************/


nabto_coap_code nabto_device_coap_method_to_code(NabtoDeviceCoapMethod method)
{
    switch(method) {
        case NABTO_DEVICE_COAP_GET: return NABTO_COAP_CODE_GET;
        case NABTO_DEVICE_COAP_POST: return NABTO_COAP_CODE_POST;
        case NABTO_DEVICE_COAP_PUT: return NABTO_COAP_CODE_PUT;
        case NABTO_DEVICE_COAP_DELETE: return NABTO_COAP_CODE_DELETE;
    }
    // Should hopefully not happen, since all possibilities should be covered in switch
    return NABTO_COAP_CODE_GET;
}

void nabto_device_coap_resource_future_resolver(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data)
{
   struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)data;
   req->handler((NabtoDeviceCoapRequest*)req, req->userData);
}

void nabto_device_coap_resource_handler(struct nabto_coap_server_request* request, void* userData)
{
    struct nabto_device_coap_resource* resource = (struct nabto_device_coap_resource*)userData;

    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)malloc(sizeof(struct nabto_device_coap_request));
    req->dev = resource->dev;
    req->req = request;
    req->handler = resource->handler;
    req->userData = resource->userData;

    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)resource->dev);
    nabto_api_future_set_error_code(fut, NABTO_DEVICE_EC_OK);
    nabto_device_future_set_callback(fut, &nabto_device_coap_resource_future_resolver, req);
    nabto_api_future_queue_post(&resource->dev->queueHead, fut);
}
