#include <nabto/nabto_device_experimental.h>

#include <api/nabto_device_authorization.h>
#include <api/nabto_device_event_handler.h>
#include <api/nabto_device_defines.h>
#include <api/nabto_device_error.h>

#include <platform/np_error_code.h>

struct nabto_device_listen_new_authorization_request_context {
    struct nabto_device_context* dev;
    struct nabto_device_listener* listener;
    NabtoDeviceEvent* userEvent;
};

np_error_code nabto_device_authorization_listener_callback(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData)
{
    (void)future;
    np_error_code retEc = NABTO_EC_OK;
    struct nabto_device_authorization_module* ctx = (struct nabto_device_authorization_module*)listenerData;
    if (ec == NABTO_EC_OK) {
        // resolve authorization request to listeners request.
        struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)eventData;
        nabto_device_authorization_request_ref_inc(authReq);
        *ctx->request = (NabtoDeviceAuthorizationRequest*)authReq;
    } else if (ec == NABTO_EC_OUT_OF_MEMORY) {
        // new auth request cannot be added to the auth queue.
    } else if (ec == NABTO_EC_ABORTED) {
        // listener has been freed.
    } else if (ec == NABTO_EC_STOPPED) {
        // listener has been stopped.
    }
    return retEc;
}

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError  NABTO_DEVICE_API
nabto_device_authorization_request_init_listener(NabtoDevice* device, NabtoDeviceListener* authorizationListener)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listener* listener = (struct nabto_device_listener*)authorizationListener;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (dev->authorization.listener != NULL) {
        ec = NABTO_EC_IN_USE;
    } else {
        ec = nabto_device_listener_init(dev, listener, NABTO_DEVICE_LISTENER_TYPE_AUTHORIZATION, &nabto_device_authorization_listener_callback, &dev->authorization);
        if (ec == NABTO_EC_OK) {
            dev->authorization.listener = listener;
        }
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return nabto_device_error_core_to_api(ec);
}

/**
 * Wait for a new Authorization request.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_listener_new_authorization_request(NabtoDeviceListener* authorizationListener, NabtoDeviceFuture* future, NabtoDeviceAuthorizationRequest** request)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)authorizationListener;
    struct nabto_device_context* dev = listener->dev;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;

    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (nabto_device_listener_get_type(listener) != NABTO_DEVICE_LISTENER_TYPE_AUTHORIZATION) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_INVALID_ARGUMENT);
    } else {
        np_error_code ec = nabto_device_listener_get_status(listener);
        if (ec != NABTO_EC_OK) {
            nabto_device_future_resolve(fut, nabto_device_error_core_to_api(ec));
        } else {
            ec = nabto_device_listener_init_future(listener, fut);
            if (ec != NABTO_EC_OK) {
                nabto_device_future_resolve(fut, ec);
            } else {
                *request = NULL;
                dev->authorization.request = request;
                nabto_device_listener_try_resolve(listener);
            }
        }
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return;
}
