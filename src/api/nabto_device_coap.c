#include "nabto_device_coap.h"

#include <api/nabto_device_defines.h>

#include <api/nabto_api_future_queue.h>
#include <api/nabto_device_event_handler.h>
#include <api/nabto_device_future.h>
#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

// TODO serveral coap module functions does not return errors on failures, when fixed, add error handling here as well
void nabto_device_coap_listener_callback(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData);

/*******************************************
 * COAP API Start
 *******************************************/

NabtoDeviceError  NABTO_DEVICE_API
nabto_device_coap_listener_new(NabtoDevice* device, NabtoDeviceCoapMethod method, const char** pathSegments, NabtoDeviceListener** deviceListener)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_coap_resource* res = calloc(1,sizeof(struct nabto_device_coap_resource));
    if (res == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }

    res->dev = dev;

    nabto_device_threads_mutex_lock(dev->eventMutex);

    struct nabto_device_listener* listener = nabto_device_listener_new(dev, NABTO_DEVICE_LISTENER_TYPE_COAP, &nabto_device_coap_listener_callback, res);
    if (listener == NULL) {
        free(res);
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }
    res->listener = listener;

    nabto_coap_server_add_resource(nc_coap_server_get_server(&dev->core.coapServer), nabto_device_coap_method_to_code(method), pathSegments, &nabto_device_coap_resource_handler, res);

    res->next = dev->coapResourceHead;
    dev->coapResourceHead = res;

    nabto_device_threads_mutex_unlock(dev->eventMutex);

    *deviceListener = (NabtoDeviceListener*)listener;
    return NABTO_DEVICE_EC_OK;
}

void nabto_device_coap_free_resources(struct nabto_device_context* device)
{
    struct nabto_device_coap_resource* resource = device->coapResourceHead;
    while(resource != NULL) {
        struct nabto_device_coap_resource* current = resource;
        resource = resource->next;
        nabto_device_listener_set_error_code(current->listener, NABTO_EC_STOPPED);
    }
    device->coapResourceHead = NULL;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_listener_new_coap_request(NabtoDeviceListener* deviceListener, NabtoDeviceFuture** future, NabtoDeviceCoapRequest** request)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_context* dev = listener->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (nabto_device_listener_get_type(listener) != NABTO_DEVICE_LISTENER_TYPE_COAP) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return NABTO_DEVICE_EC_INVALID_LISTENER;
    }
    np_error_code ec = nabto_device_listener_get_status(listener);
    if (ec != NABTO_EC_OK) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_error_core_to_api(ec);
    }
    struct nabto_device_coap_resource* res = (struct nabto_device_coap_resource*)nabto_device_listener_get_listener_data(listener);
    if (res->futureRequest != NULL) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return NABTO_DEVICE_EC_OPERATION_IN_PROGRESS;
    }
    *request = NULL;
    res->futureRequest = (struct nabto_device_coap_request**)request;
    struct nabto_device_future* fut;
    // user reference must be set before as this call can resolve the future to the future queue
    ec = nabto_device_listener_create_future(listener, &fut);
    if (ec != NABTO_EC_OK) {
        // resetting user reference if future could not be created
        res->futureRequest = NULL;
    } else {
        *future = (NabtoDeviceFuture*)fut;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceCoapResponse* NABTO_DEVICE_API nabto_device_coap_create_response(NabtoDeviceCoapRequest* request)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    struct nabto_device_coap_response* response = req->resp;

    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    struct nabto_coap_server_response* resp = nabto_coap_server_create_response(req->req);
    response->resp = resp;
    response->dev = req->dev;
    response->req = req;
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);

    return (NabtoDeviceCoapResponse*)response;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_error_response(NabtoDeviceCoapRequest* request, uint16_t code, const char* message)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    nabto_coap_server_create_error_response(req->req, nabto_coap_uint16_to_code(code), message);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);

    return ec;
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
    int32_t cf = nabto_coap_server_request_get_content_format(req->req);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    if (contentFormat >= 0) {
        *contentFormat = cf;
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

void nabto_device_coap_listener_callback(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData)
{
    struct nabto_device_coap_resource* res = (struct nabto_device_coap_resource*)listenerData;
    if (ec == NABTO_EC_OK) {
        struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)eventData;
        if (res->futureRequest != NULL) {
            nabto_api_future_set_error_code(future, NABTO_DEVICE_EC_OK);
            *res->futureRequest = req;
            res->futureRequest = NULL;
        } else {
            NABTO_LOG_ERROR(LOG, "Tried to resolve new COAP request future, but request reference was invalid");
            nabto_api_future_set_error_code(future, NABTO_DEVICE_EC_FAILED);
            nabto_coap_server_create_error_response(req->req, NABTO_COAP_CODE(5,03), "Handler unavailable");
            free(req->resp);
            free(req);
        }
        // using the coap request structure as event structure means it will be freed when user sends the response
    } else if (ec == NABTO_EC_ABORTED) {
        // todo figure out how to remove the resource from core
        free(res);
    } else {
        // In error state requests on the listener queue will not reach the user, so they cant resolve the request
        struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)eventData;
        nabto_coap_server_create_error_response(req->req, NABTO_COAP_CODE(5,03), "Handler unavailable");
        free(req->resp);
        free(req);
    }
}

void nabto_device_coap_resource_handler(struct nabto_coap_server_request* request, void* userData)
{
    struct nabto_device_coap_resource* resource = (struct nabto_device_coap_resource*)userData;
    struct nabto_device_context* dev = resource->dev;
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)malloc(sizeof(struct nabto_device_coap_request));

    if (req == NULL) {
        nabto_device_listener_set_error_code(resource->listener, NABTO_EC_OUT_OF_MEMORY);
        nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(5,00), "Insufficient resources");
        // todo remove the resource
    } else {
        req->resp = (struct nabto_device_coap_response*)malloc(sizeof(struct nabto_device_coap_response));
        if (req->resp == NULL) {
            free(req);
            nabto_device_listener_set_error_code(resource->listener, NABTO_EC_OUT_OF_MEMORY);
            nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(5,00), "Insufficient resources");
        } else {
            req->dev = dev;
            req->req = request;

            np_error_code ec = nabto_device_listener_add_event(resource->listener, req);
            if (ec != NABTO_EC_OK) {
                nabto_coap_server_create_error_response(request, NABTO_COAP_CODE(5,00), "Insufficient resources");
                free(req->resp);
                free(req);
            }
        }
    }
}
