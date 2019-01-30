#include "nabto_device_coap.h"

#include <api/nabto_device_defines.h>

#include <api/nabto_api_future_queue.h>
#include <api/nabto_device_future.h>

#include <stdlib.h>

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
    req->req = request;
    req->handler = resource->handler;
    req->userData = resource->userData;
    
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)resource->dev);
    nabto_api_future_set_error_code(fut, NABTO_EC_OK);
    nabto_device_future_set_callback(fut, &nabto_device_coap_resource_future_resolver, req);
    nabto_api_future_queue_post(&resource->dev->queueHead, fut);
}
