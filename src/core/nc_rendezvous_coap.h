#ifndef _NC_RENDEZVOUS_COAP_H_
#define _NC_RENDEZVOUS_COAP_H_

struct nc_coap_server_context;
struct nc_rendezvous_context;
struct np_platform;


struct nc_rendezvous_coap_context {
    struct nc_coap_server_context* coap;
    struct nc_rendezvous_context* rendezvous;
    struct np_platform* platform;

};


void nc_rendezvous_coap_init(struct nc_rendezvous_coap_context* context, struct nc_coap_server_context* coap, struct nc_rendezvous_context* rendezvous);

#endif
