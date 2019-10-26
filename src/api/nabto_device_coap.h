#ifndef NABTO_DEVICE_COAP_H
#define NABTO_DEVICE_COAP_H

#include <nabto/nabto_device.h>

#include <core/nc_device.h>

struct nabto_device_coap_resource;

struct nabto_device_coap_resource {
    struct nabto_device_listener* listener;
    struct nabto_device_context* dev;
    NabtoDeviceCoapResourceHandler handler;
    void* userData;
    struct nabto_device_coap_resource* next;
    struct nabto_device_coap_request** futureRequest;
    struct nabto_coap_server_resource* resource;
};

struct nabto_device_coap_request {
    struct nabto_coap_server_request* req;
    struct nabto_device_context* dev;
};

nabto_coap_code nabto_device_coap_method_to_code(NabtoDeviceCoapMethod method);
void nabto_device_coap_resource_handler(struct nabto_coap_server_request* request, void* userData);

#endif //NABTO_DEVICE_COAP_H
