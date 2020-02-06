static void free_attribute(struct nabto_device_authorization_request_attribute* attribute)
{
    if(attribute == NULL) {
        return;
    }
    if (attribute->type == NABTO_DEVICE_AUTHORIZATION_ATTRIBUTE_TYPE_STRING) {
        free(attribute->value.string);
    }
    free(attribute);
}


static np_error_code add_number_attribute(struct np_authorization_request* request, const char* key, int64_t value)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;

    struct nabto_device_authorization_request_attribute* attribute = calloc(1, sizeof(struct nabto_device_authorization_request_attribute));

    if (attribute == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    attribute->type = NABTO_DEVICE_AUTHORIZATION_ATTRIBUTE_TYPE_NUMBER;

    attribute->key = strdup(key);
    if (attribute->key == NULL) {
        free_attribute(attribute);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    attribute->value.number = value;

    struct nabto_device_authorization_request_attribute* old = authReq->attributes;

    authReq->attributes = attribute;
    attribute->next = old;
    return NABTO_EC_OK;
}
static np_error_code add_string_attribute(struct np_authorization_request* request, const char* key, const char* value)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;

    struct nabto_device_authorization_request_attribute* attribute = calloc(1, sizeof(struct nabto_device_authorization_request_attribute));

    if (attribute == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    attribute->type = NABTO_DEVICE_AUTHORIZATION_ATTRIBUTE_TYPE_STRING;

    attribute->key = strdup(key);
    attribute->value.string = strdup(value);
    if (attribute->key == NULL || attribute->value.string == NULL) {
        free_attribute(attribute);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    attribute->value.number = value;

    struct nabto_device_authorization_request_attribute* old = authReq->attributes;

    authReq->attributes = attribute;
    attribute->next = old;
    return NABTO_EC_OK;
}

struct nabto_device_authorization_request_attribute* get_attribute(struct nabto_device_authorization_request* authReq, size_t index)
{
    struct nabto_device_authorization_request_attribute* param = authReq->parameters;

    for (size_t i = 0; i < index && param != NULL; i++) {
        param = param->next;
    }
    return param;
}

size_t get_attributes_size(struct nabto_device_authorization_request* authReq)
{
    size_t i = 0;
    struct nabto_device_authorization_request_attribute* param = authReq->parameters;

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
 * Get the type of the attribute with the given index.
 */
NABTO_DEVICE_DECL_PREFIX NabtoDeviceAutorizationAttributeType NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_type(NabtoDeviceAuthorizationRequest* request, size_t index)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;
    struct nabto_device_context* dev = authReq->module->device;

    NabtoDeviceAutorizationAttributeType type = NABTO_DEVICE_AUTHORIZATION_ATTRIBUTE_TYPE_NUMBER;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    struct nabto_device_authorization_request_attribute* attribute = get_attribute(authReq, index);

    type = attribute->type;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return type;
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
    return NABTO_DEVICE_EC_NOT_IMPLEMENTED;
}

/**
 * Retrieve a string value for a key, if the key is not a string the behavior is undefined.
 */
NABTO_DEVICE_DECL_PREFIX const char* NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_string(NabtoDeviceAuthorizationRequest* request, size_t index)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;
    struct nabto_device_context* dev = authReq->module->device;

    const char* ret;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    struct nabto_device_authorization_request_attribute* attribute = get_attribute(authReq, index);
    ret = attribute->value.string;

    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return ret;
}

/**
 * Retrieve a number value for a key, if the key is not a number, the behavior is undefined.
 */
NABTO_DEVICE_DECL_PREFIX int64_t NABTO_DEVICE_API
nabto_device_authorization_request_get_attribute_number(NabtoDeviceAuthorizationRequest* request, size_t index)
{
    struct nabto_device_authorization_request* authReq = (struct nabto_device_authorization_request*)request;
    struct nabto_device_context* dev = authReq->module->device;
    int64_t ret;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    struct nabto_device_authorization_request_attribute* attribute = get_attribute(authReq, index);
    ret = attribute->value.number;
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return ret;
}
