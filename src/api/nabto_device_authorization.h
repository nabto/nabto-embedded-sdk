#ifndef NABTO_DEVICE_AUTHORIZATION_H
#define NABTO_DEVICE_AUTHORIZATION_H

#include <platform/np_event_queue.h>
#include <platform/np_authorization.h>

struct nabto_device_context;

struct nabto_device_authorization_request_attribute {
    struct nabto_device_authorization_request_attribute* next;
    const char* key;
    NabtoDeviceAutorizationAttributeType type;
    union {
        const char* str;
        int64_t number;
    } value;
};

struct nabto_device_authorization_request {
    struct nabto_device_authorization_module* module;
    struct nabto_device_authorization_request_attribute* attributes;
    uint64_t connectionReference;
    const char* action;

    /**
     * True if the api is done and has freed the request, either it has not
     * received the request or it has received it handled it and freed it.
     */
    bool apiDone;

    /**
     * True when free has been called on the object from the platform.
     */
    bool platformDone;

    struct np_event verdictEvent;
    bool verdict;

    np_authorization_request_callback verdictCallback;
    void* verdictCallbackUserData;
};

struct nabto_device_authorization_module {
    struct np_platform* pl;
    NabtoDeviceAuthorizationRequest** request;
    struct nabto_device_listener* listener;
    struct nabto_device_context* device;
};

void nabto_device_authorization_init_module(struct nabto_device_context* context);

#endif
