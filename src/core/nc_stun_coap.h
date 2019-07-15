#ifndef _NC_STUN_COAP_H_
#define _NC_STUN_COAP_H_

struct nc_stun_contex;
struct nc_coap_server_context;
struct np_platform;
struct nabto_coap_server_request;

struct nc_stun_coap_context {
    struct nc_stun_context* stun;
    struct nc_coap_server_context* coap;
    struct nc_device_context* device;
    struct np_platform* pl;
    struct nabto_coap_server_request* stunRequest;
};

void nc_stun_coap_init(struct nc_stun_coap_context* context, struct np_platform* platform, struct nc_coap_server_context* coap, struct nc_stun_context* stun);

void nc_stun_coap_deinit(struct nc_stun_coap_context* context);

#endif
