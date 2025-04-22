#ifndef NABTO_DEVICE_AUTHORIZATION_H
#define NABTO_DEVICE_AUTHORIZATION_H

#include <nabto/nabto_device.h>
#include <platform/interfaces/np_event_queue.h>
#include <platform/np_authorization.h>

#include <nn/llist.h>

struct nabto_device_context;

struct nabto_device_authorization_request_attribute {
    struct nabto_device_authorization_request_attribute* next;
    char* key;
    char* value;
};

/**
 * Lifetime of authorization requests.
 *
 * First the request is created the place which needs to make the
 * access control request. Then the request is either freeed or put
 * into the access control check queue.
 *
 * The request is then removed from the queue and given to a user
 * application which makes a verdict and calls free on the request.
 *
 * The access control callback is then called to let the initiator
 * know if the request was allowed or denied.
 */

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

    struct np_event* verdictEvent;
    bool verdict;
    bool verdictDone;

    struct nn_llist_node eventListNode;

    np_authorization_request_callback verdictCallback;
    void* verdictCallbackUserData1;
    void* verdictCallbackUserData2;
    void* verdictCallbackUserData3;


    size_t refCount;
};

struct nabto_device_authorization_module {
    struct np_platform* pl;
    NabtoDeviceAuthorizationRequest** request;
    struct nabto_device_listener* listener;
    struct nabto_device_context* device;
};

void nabto_device_authorization_init_module(struct nabto_device_context* context);

void nabto_device_authorization_request_ref_inc(struct nabto_device_authorization_request* authReq);
void nabto_device_authorization_request_ref_dec(struct nabto_device_authorization_request* authReq);

#endif
