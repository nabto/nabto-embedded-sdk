#include <nabto/nabto_device_experimental.h>
#include <platform/np_platform.h>
#include <platform/np_error_code.h>

#include <platform/np_logging.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_allocator.h>

#include "nabto_device_authorization.h"
#include "nabto_device_defines.h"
#include "nabto_device_event_handler.h"

#include <nn/string.h>

#define LOG NABTO_LOG_MODULE_API

/**
 * Functions implementing the np_authorization platform module.
 */
static struct np_authorization_request* create_request(struct np_platform* pl, uint64_t connectionRef, const char* action);
static void discard_request(struct np_authorization_request* request);
static np_error_code add_string_attribute(struct np_authorization_request* request, const char* key, const char* value);

static void check_access(struct np_authorization_request* authorizationRequest, np_authorization_request_callback callback, void* userData1, void* userData2, void* userData3);

/**
 * Helper functions
 */
static void do_verdict(struct nabto_device_authorization_request* authReq, bool verdict);
static void handle_verdict(void* userData);

struct np_authorization_request* create_request(struct np_platform* pl, uint64_t connectionRef, const char* action)
{
    struct nabto_device_authorization_request* request = np_calloc(1, sizeof(struct nabto_device_authorization_request));
    if (request == NULL) {
        return NULL;
    }
    request->connectionReference = connectionRef;
    request->action = action;
    request->attributes = NULL;
    request->verdictDone = false;
    request->module = pl->authorizationData;
    request->refCount = 0;

    np_error_code ec;
    ec = np_event_queue_create_event(&pl->eq, handle_verdict, request, &request->verdictEvent);
    if (ec != NABTO_EC_OK) {
        np_free(request);
        return NULL;
    }

    // increment for the platform, either decremented by discard request or handle access
    nabto_device_authorization_request_ref_inc(request);
    return (struct np_authorization_request*)request;
}

void discard_request(struct np_authorization_request* request)
{
    struct nabto_device_authorization_request* r = (struct nabto_device_authorization_request*)request;

    // either the request is discarded or a verdict is made for the platform.
    nabto_device_authorization_request_ref_dec(r);
}

void handle_verdict(void* userData)
{
    struct nabto_device_authorization_request* authReq = userData;
    authReq->verdictCallback(authReq->verdict, authReq->verdictCallbackUserData1, authReq->verdictCallbackUserData2, authReq->verdictCallbackUserData3);
    nabto_device_authorization_request_ref_dec(authReq);
}

void check_access(struct np_authorization_request* authorizationRequest, np_authorization_request_callback callback, void* userData1, void* userData2, void* userData3)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)authorizationRequest;
    authReq->apiDone = false;

    struct np_platform* pl = authReq->module->pl;
    struct nabto_device_authorization_module* module = pl->authorizationData;
    struct nabto_device_listener* listener = module->listener;

    authReq->verdictCallback = callback;
    authReq->verdictCallbackUserData1 = userData1;
    authReq->verdictCallbackUserData2 = userData2;
    authReq->verdictCallbackUserData3 = userData3;

    if (listener) {
        if (nabto_device_listener_add_event(listener, &authReq->eventListNode, authReq) == NABTO_EC_OK) {
            return;
        }
        NABTO_LOG_ERROR(LOG, "Authorization request could not be added to listener queue.");
    } else {
        NABTO_LOG_ERROR(LOG, "No Authorization listener is set for the device, denying the authorization request");
    }

    // if we end here the request is not added to the listener.
    do_verdict(authReq, false);
}


void do_verdict(struct nabto_device_authorization_request* authReq, bool verdict)
{
    if (authReq->verdictDone == false) {
        struct np_platform* pl = authReq->module->pl;
        authReq->verdict = verdict;
        authReq->verdictDone = true;
        np_event_queue_post(&pl->eq, authReq->verdictEvent);
    }
}

/**
 * Implementation of functions exposed throud the SDK
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_free(NabtoDeviceAuthorizationRequest* request)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;
    struct nabto_device_context* dev = authReq->module->device;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    // Set the verdict if free is called without having set a verdict first.
    if (authReq->verdictDone == false) {
        do_verdict(authReq, false);
    }

    // free is called from the user application it has a reference to the authreq
    nabto_device_authorization_request_ref_dec(authReq);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

/**
 * Call this function to inform the application that the authorization
 * request was denied.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_verdict(NabtoDeviceAuthorizationRequest* request, bool verdict)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;
    struct nabto_device_context* dev = authReq->module->device;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    do_verdict(authReq, verdict);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
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
    struct nabto_device_authorization_request* r = (struct nabto_device_authorization_request*)request;
    return r->action;
}

/**
 * Get the connection reference this authorization request originates from.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceConnectionRef NABTO_DEVICE_API
nabto_device_authorization_request_get_connection_ref(NabtoDeviceAuthorizationRequest* request)
{
    struct nabto_device_authorization_request* r = (struct nabto_device_authorization_request*)request;
    return r->connectionReference;
}
static void free_attribute(struct nabto_device_authorization_request_attribute* attribute)
{
    if(attribute == NULL) {
        return;
    }

    np_free(attribute->value);
    np_free(attribute->key);
    np_free(attribute);
}


np_error_code add_string_attribute(struct np_authorization_request* request, const char* key, const char* value)
{
    if (request == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;

    struct nabto_device_authorization_request_attribute* attribute = np_calloc(1, sizeof(struct nabto_device_authorization_request_attribute));

    if (attribute == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    attribute->key = nn_strdup(key, np_allocator_get());
    attribute->value = nn_strdup(value, np_allocator_get());
    if (attribute->key == NULL || attribute->value == NULL) {
        free_attribute(attribute);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    struct nabto_device_authorization_request_attribute* old = authReq->attributes;

    authReq->attributes = attribute;
    attribute->next = old;
    return NABTO_EC_OK;
}

struct nabto_device_authorization_request_attribute* get_attribute(struct nabto_device_authorization_request* authReq, size_t index)
{
    struct nabto_device_authorization_request_attribute* param = authReq->attributes;

    for (size_t i = 0; i < index && param != NULL; i++) {
        param = param->next;
    }
    return param;
}

size_t get_attributes_size(struct nabto_device_authorization_request* authReq)
{
    size_t i = 0;
    struct nabto_device_authorization_request_attribute* param = authReq->attributes;

    for (i = 0; param != NULL; i++) {
        param = param->next;
    }
    return i;
}

/**
 * Get the amount of attributes this authorization request contains.
 */
NABTO_DEVICE_DECL_PREFIX size_t NABTO_DEVICE_API
nabto_device_authorization_request_get_attributes_size(NabtoDeviceAuthorizationRequest* request)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;
    struct nabto_device_context* dev = authReq->module->device;
    size_t attributesSize;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    attributesSize = get_attributes_size(authReq);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return attributesSize;
}

/**
 * Get a name for an attribute
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_name(NabtoDeviceAuthorizationRequest* request, size_t index)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;
    struct nabto_device_context* dev = authReq->module->device;

    const char* ret;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_authorization_request_attribute* attribute = get_attribute(authReq, index);
    ret = attribute->key;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ret;
}

/**
 * Retrieve a string value for a key.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_value(NabtoDeviceAuthorizationRequest* request, size_t index)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;
    struct nabto_device_context* dev = authReq->module->device;

    const char* ret;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    struct nabto_device_authorization_request_attribute* attribute = get_attribute(authReq, index);
    ret = attribute->value;

    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return ret;
}

void nabto_device_authorization_init_module(struct nabto_device_context* context)
{
    struct np_platform* pl = &context->pl;

    struct nabto_device_authorization_module* module = &context->authorization;

    pl->authorizationData = module;

    module->pl = pl;
    module->request = NULL;
    module->listener = NULL;
    module->device = context;

    pl->authorization.create_request = create_request;
    pl->authorization.discard_request = discard_request;
    pl->authorization.add_string_attribute = add_string_attribute;
    pl->authorization.check_access = check_access;
}


void nabto_device_authorization_request_ref_inc(struct nabto_device_authorization_request* authReq)
{
    authReq->refCount++;
}

void nabto_device_authorization_request_ref_dec(struct nabto_device_authorization_request* authReq)
{
    authReq->refCount--;
    if (authReq->refCount == 0) {
        struct nabto_device_authorization_request_attribute* param = authReq->attributes;

        for (size_t i = 0; param != NULL; i++) {
            struct nabto_device_authorization_request_attribute* old = param;
            param = param->next;
            free_attribute(old);
        }

        struct np_platform* pl = authReq->module->pl;
        struct np_event_queue* eq = &pl->eq;
        np_event_queue_destroy_event(eq, authReq->verdictEvent);
        np_free(authReq);
    }
}
