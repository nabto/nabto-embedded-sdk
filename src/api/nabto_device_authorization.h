#ifndef NABTO_DEVICE_AUTHORIZATION_H
#define NABTO_DEVICE_AUTHORIZATION_H



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
    struct nabto_device_authorization_request_attribute* attributes;
    uint64_t connectionReferece;
    const char* action;

    /**
     * True if the api is done handling the request, either it has not
     * received the request or it has received it and handled it.
     */
    bool apiFreed;
    bool platformFreed;

};

#endif
