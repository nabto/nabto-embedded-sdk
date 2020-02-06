#include <nabto/nabto_device_experimental.h>
#include <platform/np_platform.h>
#include <platform/np_error_code.h>

#include <platform/np_logging.h>

#include "nabto_device_authorization.h"
#include "nabto_device_defines.h"
#include "nabto_device_event_handler.h"

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

/**
 * Functions implementing the np_authorization platform module.
 */
static struct np_authorization_request* create_request(struct np_platform* pl, uint64_t connectionRef, const char* action);
static void discard_request(struct np_authorization_request* request);
static np_error_code add_number_attribute(struct np_authorization_request* request, const char* key, int64_t value);
static np_error_code add_string_attribute(struct np_authorization_request* request, const char* key, const char* value);

static void check_access(struct np_authorization_request* authorizationRequest, np_authorization_request_callback callback, void* userData);

/**
 * Helper functions
 */
static void free_request_when_unused(struct nabto_device_authorization_request* request);


void nabto_device_authorization_init_platform(struct np_platform* pl)
{
    pl->authorization.create_request = create_request;
    pl->authorization.discard_request = discard_request;
    pl->authorization.add_number_attribute = add_number_attribute;
    pl->authorization.add_string_attribute = add_string_attribute;
    pl->authorization.check_access = check_access;
}


struct np_authorization_request* create_request(struct np_platform* pl, uint64_t connectionRef, const char* action)
{
    struct nabto_device_authorization_request* request = calloc(1, sizeof(struct nabto_device_authorization_request));
    request->connectionReference = connectionRef;
    request->action = action;
    request->attributes = NULL;
    request->apiDone = true;
    request->platformDone = false;
    request->module = pl->authorizationData;

    return (struct np_authorization_request*)request;
}

void discard_request(struct np_authorization_request* request)
{
    struct nabto_device_authorization_request* r = (struct nabto_device_authorization_request*)request;
    if (r->apiDone) {

        free_request_when_unused(r);
    } else {
        r->platformDone = true;
    }
}

np_error_code add_number_attribute(struct np_authorization_request* request, const char* key, int64_t value)
{
    // TODO
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
}

np_error_code add_string_attribute(struct np_authorization_request* request, const char* key, const char* value)
{
    // TODO
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
}

static void handle_verdict(void* userData)
{
    struct nabto_device_authorization_request* authReq = userData;
    authReq->verdictCallback(authReq->verdict, authReq->verdictCallbackUserData);
}

void check_access(struct np_authorization_request* authorizationRequest, np_authorization_request_callback callback, void* userData)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)authorizationRequest;
    authReq->apiDone = false;

    struct np_platform* pl = authReq->module->pl;
    struct nabto_device_authorization_module* module = pl->authorizationData;
    struct nabto_device_listener* listener = module->listener;

    authReq->verdictCallback = callback;
    authReq->verdictCallbackUserData = userData;


    if (listener) {
        if (nabto_device_listener_add_event(listener, authReq) == NABTO_EC_OK) {
            return;
        } else {
            NABTO_LOG_ERROR(LOG, "Authorization request could not be added to listener queue.");
        }
    } else {
        NABTO_LOG_ERROR(LOG, "No Authorization listener is set for the device, denying the authorization request");
    }

    // if we end here the request is not added to the listener.
    authReq->verdict = false;
    np_event_queue_post(pl, &authReq->verdictEvent, handle_verdict, authReq);

}


/**
 * Implementation of functions exposed throud the SDK
 */


NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_free(NabtoDeviceAuthorizationRequest* request)
{
// TODO
    // if the request is freed by the platform then do a real free.
}

/**
 * Call this function to inform the application that the authorization
 * request has been allowed.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_allow(NabtoDeviceAuthorizationRequest* request)
{
    // TODO synchronize
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;
    struct np_platform* pl = authReq->module->pl;
    authReq->verdict = true;
    np_event_queue_post(pl, &authReq->verdictEvent, handle_verdict, authReq);
}

/**
 * Call this function to inform the application that the authorization
 * request was denied.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_deny(NabtoDeviceAuthorizationRequest* request)
{
    // TODO synchronize
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;
    struct np_platform* pl = authReq->module->pl;
    authReq->verdict = false;
    np_event_queue_post(pl, &authReq->verdictEvent, handle_verdict, authReq);
}

/**
 * Get the action associated with the request.
 *
 * The string should not be freed and the lifetime is limited by the
 * call to nabto_device_authorization_request_free
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_action(NabtoDeviceAuthorizationRequest* request)
{
    // TODO synchronize
    struct nabto_device_authorization_request* r = (struct nabto_device_authorization_request*)request;
    return r->action;
}

/**
 * Get the connection reference this authorization request originates from.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceConnectionRef NABTO_DEVICE_API
nabto_device_authorization_request_get_connection_ref(NabtoDeviceAuthorizationRequest* request)
{
    // TODO synchronize
    struct nabto_device_authorization_request* r = (struct nabto_device_authorization_request*)request;
    return r->connectionReference;
}

/**
 * Get the amount of attributes this authorization request contains.
 */
NABTO_DEVICE_DECL_PREFIX size_t NABTO_DEVICE_API
nabto_device_authorization_request_get_attributes_size(NabtoDeviceAuthorizationRequest* request)
{
    // TODO
    return 0;
}

/**
 * Get the type of the attribute with the given index.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceAutorizationAttributeType NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_type(NabtoDeviceAuthorizationRequest* request, size_t index)
{
    // TODO
    return NABTO_DEVICE_AUTHORIZATION_ATTRIBUTE_TYPE_STRING;
}

/**
 * Get an index of the attribute with a given key
 *
 * @return NABTO_DEVICE_EC_OK if the key exists
 *         NABTO_DEVICE_EC_NOT_FOUND if the key does not exists.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_by_name(NabtoDeviceAuthorizationRequest* request, const char* name, size_t* index)
{
    // TODO
    return NABTO_DEVICE_EC_NO_DATA;
}

/**
 * Retrieve a string value for a key, if the key is not a string the behavior is undefined.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_string(NabtoDeviceAuthorizationRequest* request, size_t index)
{
    // TODO
    return "";
}

/**
 * Retrieve a number value for a key, if the key is not a number, the behavior is undefined.
 */
NABTO_DEVICE_DECL_PREFIX int64_t NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_number(NabtoDeviceAuthorizationRequest* request, size_t index)
{
    // TODO
    return 0;
}


static void free_request_when_unused(struct nabto_device_authorization_request* request)
{
    // TODO
}


void nabto_device_authorization_init_module(struct nabto_device_context* context)
{
    struct np_platform* pl = &context->pl;

    struct nabto_device_authorization_module* module = &context->authorization;

    pl->authorizationData = module;

    module->pl = pl;
    module->request = NULL;
    module->listener = NULL;

    pl->authorization.create_request = create_request;
    pl->authorization.discard_request = discard_request;
    pl->authorization.add_number_attribute = add_number_attribute;
    pl->authorization.add_string_attribute = add_string_attribute;
    pl->authorization.check_access = check_access;


}
