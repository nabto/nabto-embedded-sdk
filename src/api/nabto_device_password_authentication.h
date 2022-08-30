#ifndef _NABTO_DEVICE_PASSWORD_AUTHENTICATION_H_
#define _NABTO_DEVICE_PASSWORD_AUTHENTICATION_H_

#include <nabto/nabto_device_config.h>
#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <nn/llist.h>

//struct nc_spake2_password_request;

#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)

struct nabto_device_context;
struct nc_spake2_password_request;

struct nabto_device_password_authentication_request {
    struct nabto_device_context* dev;
    bool handled;
    struct nc_spake2_password_request* passwordRequest;
    struct nn_llist_node eventListNode;
};

/**
 * Init the module and add coap listeners.
 */
void nabto_device_password_authentication_init(struct nabto_device_context* context);

#endif

#endif
