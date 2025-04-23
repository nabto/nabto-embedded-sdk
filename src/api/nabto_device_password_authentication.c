#include "nabto_device_password_authentication.h"
#include <api/nabto_device_defines.h>
#include <api/nabto_device_error.h>
#include <api/nabto_device_listener.h>
#include <api/nabto_device_threads.h>
#include <nabto/nabto_device_config.h>
#include <nabto/nabto_device_experimental.h>

#include <core/nc_spake2.h>

#include <nn/string.h>
#include <platform/np_allocator.h>

#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)

static void nabto_device_password_authentication_request_free_internal(struct nabto_device_password_authentication_request* r);

/**
 * Handler which is registered in the core to handle new password requests.
 */
static np_error_code password_request_handler(struct nc_spake2_password_request* req, void* data);

/**
 * Password authentication listener callback.
 *
 * This callback is called from the nabto_device_listener which is created to
 * receive password authentication requests from the core.
 *
 * @param ec NABTO_EC_OK if the function should put the password authentication
 *           request in the eventData into the password authentication request in the
 *           listenerData.
 *           NABTO_EC_STOPPED if the listener has been stopped. Password
 *           authentication requests in eventData should be cleaned up as the
 *           application will not receive these password authentication
 *           requests.
 *           NABTO_EC_ABORTED if the listener is ready to be freed, no more
 *           callbacks will be received after this call.
 *
 * @param eventData An password authentication request from the core.
 * @param listenerData A datastructure holding the listener. In this case it is
 * the listener it self.
 */
np_error_code nabto_device_password_authentication_listener_resolve_event(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData)
{
    (void)future; (void)eventData;
    struct nabto_device_listener* listener = listenerData;

    if (ec == NABTO_EC_ABORTED) {
        struct nabto_device_context* dev = listener->dev;
        nc_spake2_clear_password_request_callback(&dev->core.spake2);
    } else if (ec == NABTO_EC_STOPPED) {
        struct nabto_device_password_authentication_request* r = (struct nabto_device_password_authentication_request*)eventData;
        nabto_device_password_authentication_request_free_internal(r);
    }
    // In other cases, The item in eventData needs to be converted to data on
    // the future. this uses the generic future resolve data approach in the
    // listener and then this function does not need to care about it.

    return NABTO_EC_OK;
}

bool NABTO_DEVICE_API
nabto_device_connection_is_password_authenticated(NabtoDevice* device, NabtoDeviceConnectionRef ref)
{
    // find the connection
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    bool passwordAuthenticated = false;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nc_connection* connection = nc_device_connection_from_ref(&dev->core, ref);
    if (connection != NULL) {
        passwordAuthenticated = nc_connection_is_password_authenticated(connection);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return passwordAuthenticated;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_password_authentication_username(NabtoDevice* device, NabtoDeviceConnectionRef ref, char** username)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    *username = NULL;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nc_connection* connection = nc_device_connection_from_ref(&dev->core, ref);
    if (connection == NULL) {
        ec = NABTO_DEVICE_EC_INVALID_CONNECTION;
    } else if (connection->username[0] == 0) {
        ec = NABTO_DEVICE_EC_INVALID_STATE;
    } else {
        *username = nn_strdup(connection->username, np_allocator_get());
        if (*username == NULL) {
            ec = NABTO_DEVICE_EC_OUT_OF_MEMORY;
        } else {
            ec = NABTO_DEVICE_EC_OK;
        }
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_password_authentication_request_init_listener(NabtoDevice* device, NabtoDeviceListener* passwordAuthenticationListener)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listener* listener = (struct nabto_device_listener*)passwordAuthenticationListener;
    np_error_code ec = NABTO_EC_OK;

    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (dev->core.spake2.passwordRequestHandler != NULL) {
        ec = NABTO_EC_IN_USE;
    } else {
        ec = nabto_device_listener_init(dev, listener, NABTO_DEVICE_LISTENER_TYPE_PASSWORD_REQUESTS, &nabto_device_password_authentication_listener_resolve_event, listener);

        if (ec == NABTO_EC_OK) {
            nc_spake2_set_password_request_callback(&dev->core.spake2, password_request_handler, listener);
        }
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return nabto_device_error_core_to_api(ec);
}

np_error_code password_request_handler(struct nc_spake2_password_request* req, void* data)
{
    struct nabto_device_password_authentication_request* r = np_calloc(1, sizeof(struct nabto_device_password_authentication_request));
    if (r == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    struct nabto_device_listener* listener = data;
    r->passwordRequest = req;
    r->dev = listener->dev;

    np_error_code ec = nabto_device_listener_add_event(listener, &r->eventListNode, r);
    return ec;
}

const char* NABTO_DEVICE_API
nabto_device_password_authentication_request_get_username(NabtoDevicePasswordAuthenticationRequest* request)
{
    struct nabto_device_password_authentication_request* req = (struct nabto_device_password_authentication_request*)request;
    struct nabto_device_context* dev = req->dev;
    struct nc_spake2_password_request* passwordRequest = req->passwordRequest;
    const char* response = NULL;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (req->handled) {
        response = NULL;
    } else {
        response = passwordRequest->username;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return response;
}

/**
 * Set password for the user.
 */
NabtoDeviceError NABTO_DEVICE_API
nabto_device_password_authentication_request_set_password(NabtoDevicePasswordAuthenticationRequest* request, const char* password)
{
    struct nabto_device_password_authentication_request* req = (struct nabto_device_password_authentication_request*)request;
    struct nabto_device_context* dev = req->dev;
    struct nc_spake2_password_request* passwordRequest = req->passwordRequest;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (req->handled) {
        ec = NABTO_DEVICE_EC_INVALID_STATE;
    } else {
        nc_spake2_password_ready(passwordRequest, password);
        req->handled = true;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}



/**
 * Free a password authentication request.
 */
void NABTO_DEVICE_API nabto_device_password_authentication_request_free(NabtoDevicePasswordAuthenticationRequest* request)
{
    struct nabto_device_password_authentication_request* req = (struct nabto_device_password_authentication_request*)request;
    struct nabto_device_context* dev = req->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    nabto_device_password_authentication_request_free_internal(req);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

void NABTO_DEVICE_API nabto_device_password_authentication_request_free_internal(struct nabto_device_password_authentication_request* req)
{
    if (!req->handled) {
        nc_spake2_password_ready(req->passwordRequest, NULL);
    }
    np_free(req);
}

void NABTO_DEVICE_API
nabto_device_listener_new_password_authentication_request(NabtoDeviceListener* passwordAuthenticationListener, NabtoDeviceFuture* future, NabtoDevicePasswordAuthenticationRequest** request)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)passwordAuthenticationListener;
    struct nabto_device_context* dev = listener->dev;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (nabto_device_listener_get_type(listener) != NABTO_DEVICE_LISTENER_TYPE_PASSWORD_REQUESTS) {
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

    ec = nabto_device_listener_init_future(listener, fut);
    if (ec != NABTO_EC_OK) {
        nabto_device_future_resolve(fut, ec);
    } else {
        *request = NULL;
        listener->genericFutureResolverData = (void**)request;
        nabto_device_listener_try_resolve(listener);
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

#else

bool NABTO_DEVICE_API
nabto_device_connection_is_password_authenticated(NabtoDevice* device, NabtoDeviceConnectionRef ref)
{
    return false;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_password_authentication_username(NabtoDevice* device, NabtoDeviceConnectionRef ref, char** username)
{
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_password_authentication_request_init_listener(NabtoDevice* device, NabtoDeviceListener* passwordAuthenticationListener)
{
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
}

const char* NABTO_DEVICE_API
nabto_device_password_authentication_request_get_username(NabtoDevicePasswordAuthenticationRequest* request)
{
    return NULL;
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_password_authentication_request_set_password(NabtoDevicePasswordAuthenticationRequest* request, const char* password)
{
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
}

void NABTO_DEVICE_API nabto_device_password_authentication_request_free(NabtoDevicePasswordAuthenticationRequest* request)
{

}

void NABTO_DEVICE_API
nabto_device_listener_new_password_authentication_request(NabtoDeviceListener* passwordAuthenticationListener, NabtoDeviceFuture* future, NabtoDevicePasswordAuthenticationRequest** request)
{

}

// TODO implement NOT IMPLEMENTED password auth functions
#endif
