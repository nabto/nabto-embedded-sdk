

#icnlude "nabto_device_authorization.h"


/**
 * Functions implementing the np_authorization platform module.
 */
static struct np_authorization_request* create_request(struct np_platform* pl, uint64_t connectionRef, const char* action);
static void free_request(struct np_authorization_request* request);
static np_error_code add_number_attribute(struct np_authorization_request* request, const char* key, int64_t value);
static np_erorr_code add_string_attribute(struct np_authorization_request* request, const char* key, const char* value);

static void check_access(struct np_authorization_request* authorizationRequest, np_authorization_request_callback callback, void* userData);

/**
 * Helper functions
 */
static void free_request_when_unused(struct nabto_device_authorization_request* request);


void nabto_device_authorization_init_platform(struct np_platform* pl)
{
    pl->authorization.create_request = create_request;
    pl->authorization.free_request = free_request;
    pl->authorization.add_number_attribute = add_number_attribute;
    pl->authorization.add_string_attribute = add_string_attribute;
    pl->authorization.check_access = check_access;
}


struct np_authorization_request* create_request(struct np_platform* pl, uint64_t connectionRef, const char* action)
{
    struct nabto_device_authorization_request* request = calloc(1, sizeof(struct nabto_device_authorization_request));
    request->connectionReferece = connectionRef;
    request->action = action;
    request->attributes = NULL;
    request->apiFreed = true;
    request->platformFreed = false;

    return (struct np_authorization_request*)request;
}

void free_request(struct np_authorization_request* request)
{
    struct nabto_device_authorization_request* r = (struct nabto_device_authorization_request*)request;
    if (r->sdkDone) {

        free_authorization_request(r)
        free(r);
    } else {
        r->platformDone = true;
    }
}

np_error_code add_number_attribute(struct np_authorization_request* request, const char* key, int64_t value)
{
    // TODO
}

np_erorr_code add_string_attribute(struct np_authorization_request* request, const char* key, const char* value)
{
    // TODO
}

void check_access(struct np_authorization_request* authorizationRequest, np_authorization_request_callback callback, void* userData)
{

}


/**
 * Implementation of functions exposed throud the SDK
 */


NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_free(NabtoDeviceAuthorizationRequest* request);

/**
 * Call this function to inform the application that the authorization
 * request has been allowed.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_allow(NabtoDeviceAuthorizationRequest* request);

/**
 * Call this function to inform the application that the authorization
 * request was denied.
 */
NABTO_DEVICE_DECL_PREFIX void NABTO_DEVICE_API
nabto_device_authorization_request_deny(NabtoDeviceAuthorizationRequest* request);

/**
 * Get the action associated with the request.
 *
 * The string should not be freed and the lifetime is limited by the
 * call to nabto_device_authorization_request_free
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_action(NabtoDeviceAuthorizationRequest* request);

/**
 * Get the connection reference this authorization request originates from.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceConnectionRef NABTO_DEVICE_API
nabto_device_authorization_request_get_connection_ref(NabtoDeviceAuthorizationRequest* request);

/**
 * Get the amount of attributes this authorization request contains.
 */
NABTO_DEVICE_DECL_PREFIX size_t NABTO_DEVICE_API
nabto_device_authorization_request_get_attributes_size(NabtoDeviceAuthorizationRequest* request);

/**
 * Get the type of the attribute with the given index.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceAutorizationAttributeType NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_type(NabtoDeviceAuthorizationRequest* request, size_t index);

/**
 * Get an index of the attribute with a given key
 *
 * @return NABTO_DEVICE_EC_OK if the key exists
 *         NABTO_DEVICE_EC_NOT_FOUND if the key does not exists.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_by_name(NabtoDeviceAuthorizationRequest* request, const char* name, size_t* index);

/**
 * Retrieve a string value for a key, if the key is not a string the behavior is undefined.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_string(NabtoDeviceAuthorizationRequest* request, size_t index);

/**
 * Retrieve a number value for a key, if the key is not a number, the behavior is undefined.
 */
NABTO_DEVICE_DECL_PREFIX int64_t NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_number(NabtoDeviceAuthorizationRequest* request, size_t index);


static void free_request_when_unused(struct nabto_device_authorization_request* request)
{
    // TODO
}
