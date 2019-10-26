#include "nabto_device_coap.h"

#include <coap/nabto_coap_server.h>

#include <api/nabto_device_defines.h>

#include <api/nabto_api_future_queue.h>
#include <api/nabto_device_event_handler.h>
#include <api/nabto_device_future.h>
#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

// TODO serveral coap module functions does not return errors on failures, when fixed, add error handling here as well
np_error_code nabto_device_coap_listener_callback(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData);

NabtoDeviceError nabto_device_coap_error_module_to_api(nabto_coap_error ec) {
    switch(ec) {
        case NABTO_COAP_ERROR_OK: return NABTO_DEVICE_EC_OK;
        case NABTO_COAP_ERROR_OUT_OF_MEMORY: return NABTO_DEVICE_EC_OUT_OF_MEMORY;
        case NABTO_COAP_ERROR_NO_CONNECTION: return NABTO_DEVICE_EC_ABORTED;
        case NABTO_COAP_ERROR_INVALID_PARAMETER: return NABTO_DEVICE_EC_INVALID_PARAMETER;
        default: return NABTO_DEVICE_EC_FAILED;
    }
}

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

    nabto_coap_error err = nabto_coap_server_add_resource(nc_coap_server_get_server(&dev->core.coapServer), nabto_device_coap_method_to_code(method), pathSegments, &nabto_device_coap_resource_handler, res, &res->resource);
    if (err != NABTO_COAP_ERROR_OK) {
        nabto_device_listener_free((NabtoDeviceListener*)listener);
        free(res);
        return nabto_device_coap_error_module_to_api(err);
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);

    *deviceListener = (NabtoDeviceListener*)listener;
    return NABTO_DEVICE_EC_OK;
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

void NABTO_DEVICE_API nabto_device_coap_request_free(NabtoDeviceCoapRequest* request)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    struct nabto_device_context* dev = req->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    nabto_coap_server_request_free(req->req);
    free(req);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}


NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_error_response(NabtoDeviceCoapRequest* request, uint16_t code, const char* message)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    nabto_coap_error err = nabto_coap_server_send_error_response(req->req, nabto_coap_uint16_to_code(code), message);
    ec = nabto_device_coap_error_module_to_api(err);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_set_code(NabtoDeviceCoapRequest* request, uint16_t code)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    nabto_coap_server_response_set_code(req->req, nabto_coap_uint16_to_code(code));
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_set_payload(NabtoDeviceCoapRequest* request,
                                                        const void* data, size_t dataSize)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    nabto_coap_error err = nabto_coap_server_response_set_payload(req->req, data, dataSize);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    return nabto_device_coap_error_module_to_api(err);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_set_content_format(NabtoDeviceCoapRequest* request, uint16_t format)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    nabto_coap_server_response_set_content_format(req->req, format);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_ready(NabtoDeviceCoapRequest* request)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    nabto_coap_error err = nabto_coap_server_response_ready(req->req);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    return nabto_device_coap_error_module_to_api(err);
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

np_error_code nabto_device_coap_listener_callback(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData)
{
    struct nabto_device_coap_resource* res = (struct nabto_device_coap_resource*)listenerData;
    np_error_code retEc;
    if (ec == NABTO_EC_OK) {
        struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)eventData;
        if (res->futureRequest != NULL) {
            retEc = NABTO_EC_OK;
            *res->futureRequest = req;
            res->futureRequest = NULL;
        } else {
            NABTO_LOG_ERROR(LOG, "Tried to resolve new COAP request future, but request reference was invalid");
            retEc = NABTO_EC_FAILED;
            // If this fails we should just keep cleaning up
            nabto_coap_server_send_error_response(req->req, NABTO_COAP_CODE(5,03), "Handler unavailable");
            free(req);
        }
        // using the coap request structure as event structure means it will be freed when user sends the response
    } else if (ec == NABTO_EC_ABORTED) {
        retEc = ec;
        free(res);
    } else {
        // In error state requests on the listener queue will not reach the user, so they cant resolve the request
        struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)eventData;
        // if this fails we should just keep cleaning up
        nabto_coap_server_send_error_response(req->req, NABTO_COAP_CODE(5,03), "Handler unavailable");
        free(req);
        retEc = ec;
    }
    return retEc;
}

void nabto_device_coap_resource_handler(struct nabto_coap_server_request* request, void* userData)
{
    struct nabto_device_coap_resource* resource = (struct nabto_device_coap_resource*)userData;
    struct nabto_device_context* dev = resource->dev;
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)malloc(sizeof(struct nabto_device_coap_request));

    if (req == NULL) {
        nabto_device_listener_set_error_code(resource->listener, NABTO_EC_OUT_OF_MEMORY);
        // ignore errors, we cannot do more than set the listener error code which is already done
        nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(5,00), "Insufficient resources");
        nabto_coap_server_request_free(request);
    } else {
        req->dev = dev;
        req->req = request;

        np_error_code ec = nabto_device_listener_add_event(resource->listener, req);
        if (ec != NABTO_EC_OK) {
            // since we are out of resources, this probably fails. Either way we keep cleaning up
            nabto_coap_server_send_error_response(request, NABTO_COAP_CODE(5,00), "Insufficient resources");
            nabto_coap_server_request_free(request);
            free(req);
        }
    }
}
