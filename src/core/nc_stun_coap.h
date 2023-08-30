#ifndef _NC_STUN_COAP_H_
#define _NC_STUN_COAP_H_

#include "nc_stun.h"
#include <platform/np_error_code.h>
#include <platform/np_types.h>

struct nc_stun_contex;
struct nc_coap_server_context;
struct np_platform;
struct nc_coap_server_request;

struct nc_stun_coap_context {
    bool deinitialized;
    struct nc_stun_context* stun;
    struct nc_coap_server_context* coap;
    struct nc_device_context* device;
    struct np_platform* pl;
    struct nc_coap_server_resource* resource;
};

// When a new coap request is received create this context and give it as callback to the async analyze function.
// when the analyze callback is resolved get the state from stunCoap and create a coap response.
struct nc_stun_coap_endpoints_request {
    struct nc_stun_coap_context* stunCoap;
    struct nc_coap_server_request* request;
    struct nc_stun_callback callback;
};

np_error_code nc_stun_coap_init(struct nc_stun_coap_context* context, struct np_platform* platform, struct nc_coap_server_context* coap, struct nc_stun_context* stun);

void nc_stun_coap_deinit(struct nc_stun_coap_context* context);

#endif
