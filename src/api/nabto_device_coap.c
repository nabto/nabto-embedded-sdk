#include "nabto_device_coap.h"

#include <coap/nabto_coap_server.h>

#include <api/nabto_device_defines.h>

#include <api/nabto_device_event_handler.h>
#include <api/nabto_device_future.h>
#include <api/nabto_device_error.h>
#include <core/nc_coap.h>
#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

np_error_code nabto_device_coap_listener_callback(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData);

/*******************************************
 * COAP API Start
 *******************************************/

NabtoDeviceError NABTO_DEVICE_API
nabto_device_coap_init_listener(NabtoDevice* device, NabtoDeviceListener* deviceListener, NabtoDeviceCoapMethod method, const char** pathSegments)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_coap_resource* res = calloc(1,sizeof(struct nabto_device_coap_resource));
    if (res == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }

    res->dev = dev;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nabto_device_listener_init(dev, listener, NABTO_DEVICE_LISTENER_TYPE_COAP, &nabto_device_coap_listener_callback, res);
    if (ec) {
        free(res);
    } else {
        res->listener = listener;

        nabto_coap_error err = nabto_coap_server_add_resource(nc_coap_server_get_server(&dev->core.coapServer), nabto_device_coap_method_to_code(method), pathSegments, &nabto_device_coap_resource_handler, res, &res->resource);
        if (err != NABTO_COAP_ERROR_OK) {
            free(res);
            ec = nc_coap_error_to_core(err);
        }
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

void NABTO_DEVICE_API
nabto_device_listener_new_coap_request(NabtoDeviceListener* deviceListener, NabtoDeviceFuture* future, NabtoDeviceCoapRequest** request)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_context* dev = listener->dev;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (nabto_device_listener_get_type(listener) != NABTO_DEVICE_LISTENER_TYPE_COAP) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_INVALID_ARGUMENT);
        return;
    }
    np_error_code ec = nabto_device_listener_get_status(listener);
    if (ec != NABTO_EC_OK) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        nabto_device_future_resolve(fut, nabto_device_error_core_to_api(ec));
        return;
    }
    struct nabto_device_coap_resource* res = (struct nabto_device_coap_resource*)nabto_device_listener_get_listener_data(listener);
    ec = nabto_device_listener_init_future(listener, fut);
    if (ec != NABTO_EC_OK) {
        nabto_device_future_resolve(fut, ec);
    } else {
        *request = NULL;
        res->futureRequest = (struct nabto_device_coap_request**)request;
        nabto_device_listener_try_resolve(listener);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
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
    ec = nc_coap_error_to_core(err);
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
    return nabto_device_error_core_to_api(nc_coap_error_to_core(err));
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
    return nabto_device_error_core_to_api(nc_coap_error_to_core(err));
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_request_get_content_format(NabtoDeviceCoapRequest* request,
                                                                               uint16_t* contentFormat)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    int32_t cf = nabto_coap_server_request_get_content_format(req->req);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    if (cf >= 0) {
        *contentFormat = cf;
        return NABTO_DEVICE_EC_OK;
    } else {
        return NABTO_DEVICE_EC_UNKNOWN;
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
        return NABTO_DEVICE_EC_UNKNOWN;
    } else {
        return NABTO_DEVICE_EC_OK;
    }
}

NabtoDeviceConnectionRef NABTO_DEVICE_API nabto_device_coap_request_get_connection_ref(NabtoDeviceCoapRequest* request)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    return req->connectionRef;
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
    (void)future;
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
            retEc = NABTO_EC_UNKNOWN;
            // If this fails we should just keep cleaning up
            nabto_coap_server_send_error_response(req->req, (nabto_coap_code)(NABTO_COAP_CODE(5,03)), "Handler unavailable");
            free(req);
        }
        // using the coap request structure as event structure means it will be freed when user sends the response
    } else if (ec == NABTO_EC_ABORTED) {
        retEc = ec;
        nabto_coap_server_remove_resource(res->resource);
        free(res);
    } else {
        // In error state requests on the listener queue will not reach the user, so they cant resolve the request
        struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)eventData;
        // if this fails we should just keep cleaning up
        nabto_coap_server_send_error_response(req->req, (nabto_coap_code)(NABTO_COAP_CODE(5,03)), "Handler unavailable");
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
        // ignore errors, we cannot do more than set the listener error code which is already done
        nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), "Insufficient resources");
        nabto_coap_server_request_free(request);
    } else {
        req->dev = dev;
        req->req = request;
        struct nc_client_connection* connection = (struct nc_client_connection*)nabto_coap_server_request_get_connection(request);
        if (connection != NULL) {
            req->connectionRef= connection->connectionRef;
        } else {
            req->connectionRef = 0;
        }

        np_error_code ec = nabto_device_listener_add_event(resource->listener, &req->eventListNode, req);
        if (ec != NABTO_EC_OK) {
            // since we are out of resources, this probably fails. Either way we keep cleaning up
            nabto_coap_server_send_error_response(request, (nabto_coap_code)(NABTO_COAP_CODE(5,00)), "Insufficient resources");
            nabto_coap_server_request_free(request);
            free(req);
        }
    }
}
